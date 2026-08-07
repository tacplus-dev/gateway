# Gateway Questions

1. **SM needs to expose grpc_health reporter for services that bypass `run()`.**
   Gateway cannot use `sm.run()` because it needs custom external TLS (LetsEncrypt/CertChain mode)
   that differs from the SM's auto-TLS (kernel-issued SPIFFE cert). The SM's health probe on 8444
   starts as NOT_SERVING in `new()` and only transitions to SERVING inside `run()` (mod.rs:1170).
   Since gateway never calls `run()`, the k8s startup probe on 8444 permanently returns NOT_SERVING.
   **Need**: A public method on SM like `set_health_serving()` or `health_reporter()` so gateway
   can manage the health probe after its own bootstrap completes. Default taken: gateway classifies
   health correctly on its main-port health service (the one k8s CAN reach); the 8444 probe remains
   stuck until this tacplus gap is closed.
