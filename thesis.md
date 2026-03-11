
# Existing solutions:
   The biggest and the most advanced is Cilium for sure. 

# On monitoring subject:
   ## Main requirement:
   The sunbect's relevance is self-evident. Since the thesis aims to demonstrate the advantages of implementing bpf, the subject should be fully accessible within the kernel or require a minimal number of transactions in user space. Data obtained in Kernel should be sufficient to picture subject's behaviour and appropriate in context.

   L7 observability decently studied and is a real deal in business, but potents a ton of drowbacks. At the very least, there's a SSL for HTTP1/1 and HPACK for HTTP2, Uhich means a lot of Uork just to get to plaintext. Futhermore, HTTP2 and SSL implementation is strongly depends on language used. Existing solutions mainly provide HTTP1/1 monitoring, and even then with difficulty: at the very least, there is the problem of fragmentation.
   Cilium and Pixie are leaders here

   DNS observability it critical in many cases inside k8s. If DNS dies, cluster dies.

Supports:
   1. Eth:
      - Vlan/Default 

TODO: 
   1. Eth.VXLAN


Not considered:
   1. Ip packet fragmentation

Code:
   1. __always_inline:
      - Although there is support for bpf-to-bpf calls, the ‘stackless’ nature and lack of context violation justify the use of __always_inline.
      - Inlined functions excessively increase the size of the bytecode, but starting with kernel 5.1, 1,000,000 instructions are available, which is more than enough.