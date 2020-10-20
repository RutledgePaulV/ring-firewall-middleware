(ns ring-firewall-middleware.core
  (:require [ring-firewall-middleware.coordination :as coord]
            [ring-firewall-middleware.cidr :as cidr]
            [ring-firewall-middleware.utils :as util]
            [ring-firewall-middleware.maintenance :as main])
  (:import [java.util.concurrent Semaphore TimeUnit]))


(defn default-forbidden-handler
  "Provides a default ring response for users who didn't meet the firewall requirements."
  ([request]
   {:status  403
    :headers {"Content-Type" "text/plain"}
    :body    "Access denied"})
  ([request respond raise]
   (respond (default-forbidden-handler request))))


(defn default-limited-handler
  "Provides a default ring response for users who exceeded the imposed limit."
  ([request]
   {:status  429
    :headers {"Content-Type" "text/plain"}
    :body    "Limit exceeded"})
  ([request respond raise]
   (respond (default-limited-handler request))))


(defn default-maintenance-handler
  "Provides a default ring response for when the server is enforcing a maintenance mode."
  ([request]
   {:status  503
    :headers {"Content-Type" "text/plain"}
    :body    "Undergoing maintenance"})
  ([request respond raise]
   (respond (default-maintenance-handler request))))


(defn wrap-allow-ips
  "Protect a ring handler with source ip authentication. Your allow-list ranges must cover
   any permitted clients as well as any intermediate proxy servers. The default allow-list
   ranges cover the entire internal network space as defined by RFC 1918 and RFC 4193.

   allow-list    - cidr ranges collection that, if matched, will result in an allowed request. optionally
                  provide a ref type in which case it will be dereferenced before use.

   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.

   "
  ([handler]
   (wrap-allow-ips handler {}))
  ([handler {:keys [allow-list deny-handler]
             :or   {allow-list   cidr/private-subnets
                    deny-handler default-forbidden-handler}}]
   (fn allow-ips-handler
     ([request]
      (let [client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain allow-list)
          (handler request)
          (deny-handler request))))
     ([request respond raise]
      (let [client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain allow-list)
          (handler request respond raise)
          (deny-handler request respond raise)))))))


(defn wrap-deny-ips
  "Protect a ring handler with source ip authentication. Your deny-list ranges must cover
   any forbidden clients / proxy servers. The default deny-list ranges cover the entire internal
   public network space.

   deny-list    - cidr ranges collection that, if matched, will result in a denied request. optionally
                  provide a ref type in which case it will be dereferenced before use.

   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.

   "
  ([handler]
   (wrap-deny-ips handler {}))
  ([handler {:keys [deny-list deny-handler]
             :or   {deny-list    cidr/public-subnets
                    deny-handler default-forbidden-handler}}]
   (fn deny-ips-handler
     ([request]
      (let [client-chain (cidr/client-ip-chain request)]
        (if-not (cidr/client-denied? client-chain deny-list)
          (handler request)
          (deny-handler request))))
     ([request respond raise]
      (let [client-chain (cidr/client-ip-chain request)]
        (if-not (cidr/client-denied? client-chain deny-list)
          (handler request respond raise)
          (deny-handler request respond raise)))))))


(defn wrap-concurrency-throttle
  "Protect a ring handler against excessive concurrency. New requests
   after the concurrency limit is already saturated will block until
   a slot is available.

   max-concurrent - the maximum number of requests to be handled concurrently
   ident-fn       - a function of a request returning an opaque identifier by which to identify the
                    semaphore. defaults to a global limit (shared by all clients) but you may set it to
                    ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                    instead or else write your own function to set it to some other group of clients
                    like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-concurrency-throttle handler {}))
  ([handler {:keys [max-concurrent ident-fn]
             :or   {max-concurrent 1
                    ident-fn       (constantly :world)}}]
   (let [stripe (coord/weak-semaphore-factory max-concurrent)]
     (fn concurrency-throttle-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (try
            (.acquire semaphore)
            (handler request)
            (finally
              (.release semaphore)))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (.acquire semaphore)
          (handler request
                   (fn [response]
                     (try
                       (respond response)
                       (finally
                         (.release semaphore))))
                   (fn [exception]
                     (try
                       (raise exception)
                       (finally
                         (.release semaphore)))))))))))


(defn wrap-concurrency-limit
  "Protect a ring handler against excessive concurrency. New requests
   after the concurrency limit is already saturated will receive a
   denied response.

   max-concurrent - the maximum number of requests to be handled concurrently
   deny-handler   - a function of a ring request that returns a ring response in the event of a denied request.
   max-wait       - the amount of time (in milliseconds) that a request should wait optimistically before
                    succeeding or returning with a denied response.
   ident-fn       - a function of a request returning an opaque identifier by which to identify the
                    semaphore. defaults to a global limit (shared by all clients) but you may set it to
                    ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                    instead or else write your own function to set it to some other group of clients
                    like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-concurrency-limit handler {}))
  ([handler {:keys [max-concurrent deny-handler ident-fn max-wait]
             :or   {max-concurrent 1
                    deny-handler   default-limited-handler
                    ident-fn       (constantly :world)
                    max-wait       50}}]
   (let [stripe (coord/weak-semaphore-factory max-concurrent)]
     (fn concurrency-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (if (.tryAcquire semaphore max-wait TimeUnit/MILLISECONDS)
            (try (handler request)
                 (finally (.release semaphore)))
            (deny-handler request))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (if (.tryAcquire semaphore max-wait TimeUnit/MILLISECONDS)
            (handler request
                     (fn [response]
                       (try
                         (respond response)
                         (finally
                           (.release semaphore))))
                     (fn [exception]
                       (try
                         (raise exception)
                         (finally
                           (.release semaphore)))))
            (deny-handler request respond raise))))))))


(defn wrap-rate-throttle
  "Protect a ring handler against excessive calls. New requests
   that would exceed the rate limit will block until making
   them would no longer exceed the rate limit.

   max-requests - the maximum number of requests allowed within the time period.
   period       - the span of the sliding window (in milliseconds) over which requests are counted.
   ident-fn     - a function of a request returning an opaque identifier by which to identify the
                  rate limiter. defaults to a global limit (shared by all clients) but you may set it to
                  ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                  instead or else write your own function to set it to some other group of clients
                  like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-rate-throttle handler {}))
  ([handler {:keys [max-requests period ident-fn]
             :or   {max-requests 100
                    period       60000
                    ident-fn     (constantly :world)}}]
   (let [striped (coord/weak-leaky-semaphore-factory max-requests period)]
     (fn rate-throttle-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (.acquire semaphore)
          (handler request)))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (.acquire semaphore)
          (handler request respond raise)))))))


(defn wrap-rate-limit
  "Protect a ring handler against excessive calls. New requests
   that would exceed the rate limit will receive a denied response.

   max-requests - the maximum number of requests allowed within the time period.
   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.
   period       - the span of the sliding window (in milliseconds) over which requests are counted.
   max-wait     - the amount of time (in milliseconds) that a request should wait optimistically before
                  succeeding or returning with a denied response.
   ident-fn     - a function of a request returning an opaque identifier by which to identify the
                  rate limiter. defaults to a global limit (shared by all clients) but you may set it to
                  ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                  instead or else write your own function to set it to some other group of clients
                  like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-rate-limit handler {}))
  ([handler {:keys [max-requests period deny-handler ident-fn max-wait]
             :or   {max-requests 500
                    period       60000
                    ident-fn     (constantly :world)
                    deny-handler default-limited-handler
                    max-wait     50}}]
   (let [striped (coord/weak-leaky-semaphore-factory max-requests period)]
     (fn rate-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (if (.tryAcquire semaphore max-wait TimeUnit/MILLISECONDS)
            (handler request)
            (deny-handler request))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (if (.tryAcquire semaphore max-wait TimeUnit/MILLISECONDS)
            (handler request respond raise)
            (deny-handler request respond raise))))))))


(defn wrap-maintenance-throttle
  "Middleware that coordinates requests to establish a maintenance mode when
   requested. When maintenance throttle is enabled any new requests will block
   but in-flight requests will be given a chance to finish prior to maintenance
   activities beginning.

   ident-fn     - a function of a request returning an opaque identifier by which to identify the
                  request group that may be flipped into maintenance mode. useful if applying
                  maintenance mode to one (of many) tenants at a time.
   bypass-list  - a set of cidr ranges that are exempt from maintenance mode restrictions.
                  useful if a set of administrators should still be able to use the site while
                  maintenance mode is otherwise active.
   "
  ([handler]
   (wrap-maintenance-throttle handler {}))
  ([handler {:keys [ident-fn bypass-list]
             :or   {ident-fn    (constantly :world)
                    bypass-list #{}}}]

   (fn maintenance-throttle-handler
     ([request]
      (let [bypassable   (util/touch bypass-list)
            client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain bypassable)
          (handler request)
          (let [{:keys [lock phaser]} (main/get-state (ident-fn request))]
            (when (some? lock) (deref lock))
            (main/register-phaser phaser)
            (try
              (handler request)
              (finally
                (main/deregister-phaser phaser)))))))

     ([request respond raise]
      (let [bypassable   (util/touch bypass-list)
            client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain bypassable)
          (handler request respond raise)
          (let [{:keys [lock phaser]} (main/get-state (ident-fn request))]
            (when (some? lock) (deref lock))
            (main/register-phaser phaser)
            (handler request
                     (fn [response]
                       (try (respond response)
                            (finally (main/deregister-phaser phaser))))
                     (fn [exception]
                       (try (raise exception)
                            (finally (main/deregister-phaser phaser))))))))))))


(defn wrap-maintenance-limit
  "Middleware that coordinates requests to establish a maintenance mode when
   requested. When maintenance mode is enabled any new requests will be denied
   but in-flight requests will be given a chance to finish prior to maintenance
   activities beginning.

   ident-fn     - a function of a request returning an opaque identifier by which to identify the
                  request group that may be flipped into maintenance mode. useful if applying
                  maintenance mode to one (of many) tenants at a time.
   bypass-list  - a set of cidr ranges that are exempt from maintenance mode restrictions.
                  useful if a set of administrators should still be able to access while
                  maintenance mode is otherwise active.
   deny-handler - a ring handler that should produce a response for requests that were denied due
                  to being in maintenance mode.
   max-wait     - the amount of time (in milliseconds) that a request should wait optimistically before
                  succeeding or returning with a denied response.
   "
  ([handler]
   (wrap-maintenance-limit handler {}))
  ([handler {:keys [ident-fn bypass-list deny-handler max-wait]
             :or   {ident-fn     (constantly :world)
                    deny-handler default-maintenance-handler
                    bypass-list  #{}
                    max-wait     50}}]

   (fn maintenance-limit-handler
     ([request]
      (let [bypassable   (util/touch bypass-list)
            client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain bypassable)
          (handler request)
          (let [{:keys [lock phaser]} (main/get-state (ident-fn request))]
            (if (and (some? lock) (= ::limited (deref lock max-wait ::limited)))
              (deny-handler request)
              (do (main/register-phaser phaser)
                  (try
                    (handler request)
                    (finally
                      (main/deregister-phaser phaser)))))))))

     ([request respond raise]
      (let [bypassable   (util/touch bypass-list)
            client-chain (cidr/client-ip-chain request)]
        (if (cidr/client-allowed? client-chain bypassable)
          (handler request respond raise)
          (let [{:keys [lock phaser]} (main/get-state (ident-fn request))]
            (if (and (some? lock) (= ::limited (deref lock max-wait ::limited)))
              (deny-handler request respond raise)
              (do (main/register-phaser phaser)
                  (handler request
                           (fn [response]
                             (try (respond response)
                                  (finally (main/deregister-phaser phaser))))
                           (fn [exception]
                             (try (raise exception)
                                  (finally (main/deregister-phaser phaser))))))))))))))



(defmacro with-maintenance-mode
  "Enables maintenance mode for the given identity and
   executes body after all in-flight requests have
   completed."
  [ident & body]
  `(let [state# (main/exclusive-lock ~ident)]
     (try
       (main/await-phaser (:phaser state#))
       ~@body
       (finally
         (main/release-lock (:lock state#))))))