package k8s

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)


type PodWatcher struct {
	clientset *kubernetes.Clientset
	cache     *PodCache
	nodeName  string
}


func NewPodWatcher(cache *PodCache, nodeName string) (*PodWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &PodWatcher{
		clientset: clientset,
		cache:     cache,
		nodeName:  nodeName,
	}, nil
}


func (w *PodWatcher) Run(ctx context.Context) error {
	
	tweakListOptions := func(options *metav1.ListOptions) {
		if w.nodeName != "" {
			options.FieldSelector = "spec.nodeName=" + w.nodeName
		}
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		w.clientset,
		0*time.Minute,
		informers.WithTweakListOptions(tweakListOptions),
	)

	informer := factory.Core().V1().Pods().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.handlePodAdd(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldPod, ok := oldObj.(*corev1.Pod)
			if !ok {
				return
			}
			newPod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}

			if oldPod.Status.PodIP != newPod.Status.PodIP {
				w.cache.Add(newPod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			w.handlePodDelete(pod)
		},
	})

	slog.Info("Starting Kubernetes Pod Informer", "node", w.nodeName)
	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		slog.Error("Timed out waiting for caches to sync")
	}

	<-ctx.Done()
	slog.Info("Shutting down Pod Informer")
	return nil
}

func (w *PodWatcher) handlePodAdd(pod *corev1.Pod) {
	w.cache.Add(pod)
}

func (w *PodWatcher) handlePodDelete(pod *corev1.Pod) {
	w.cache.Delete(pod)
}
