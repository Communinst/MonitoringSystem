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

// PodWatcher observes Kubernetes Pods and maintains a local cache.
type PodWatcher struct {
	clientset *kubernetes.Clientset
	cache     *PodCache
	nodeName  string
}

// NewPodWatcher creates a new instance of a Kubernetes informer for Pods.
func NewPodWatcher(cache *PodCache, nodeName string) (*PodWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback for local development if run out-of-cluster (e.g., make run-local)
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

// Run starts the informer and blocks until the context is canceled.
func (w *PodWatcher) Run(ctx context.Context) error {
	// Limit memory load by only watching pods placed on this specific node
	tweakListOptions := func(options *metav1.ListOptions) {
		if w.nodeName != "" {
			options.FieldSelector = "spec.nodeName=" + w.nodeName
		}
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		w.clientset,
		10*time.Minute,
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
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			w.handlePodAdd(pod)
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
