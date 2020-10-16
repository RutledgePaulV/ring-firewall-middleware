(ns ring-firewall-middleware.core
  (:require [ring-firewall-middleware.coordination :as coord]
            [ring-firewall-middleware.timer :as timer]
            [ring-firewall-middleware.cidr :as cidr]
            [ring-firewall-middleware.utils :as util])
  (:import [java.util.concurrent Semaphore]
           [java.util UUID]))


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
                     (.release semaphore)
                     (respond response))
                   (fn [exception]
                     (.release semaphore)
                     (raise exception)))))))))


(defn wrap-concurrency-limit
  "Protect a ring handler against excessive concurrency. New requests
   after the concurrency limit is already saturated will receive a
   denied response.

   max-concurrent - the maximum number of requests to be handled concurrently
   deny-handler   - a function of a ring request that returns a ring response in the event of a denied request.
   ident-fn       - a function of a request returning an opaque identifier by which to identify the
                    semaphore. defaults to a global limit (shared by all clients) but you may set it to
                    ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                    instead or else write your own function to set it to some other group of clients
                    like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-concurrency-limit handler {}))
  ([handler {:keys [max-concurrent deny-handler ident-fn]
             :or   {max-concurrent 1
                    deny-handler   default-limited-handler
                    ident-fn       (constantly :world)}}]
   (let [stripe (coord/weak-semaphore-factory max-concurrent)]
     (fn concurrency-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (if (.tryAcquire semaphore)
            (try (handler request)
                 (finally (.release semaphore)))
            (deny-handler request))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (stripe ident)]
          (if (.tryAcquire semaphore)
            (handler request
                     (fn [response]
                       (.release semaphore)
                       (respond response))
                     (fn [exception]
                       (.release semaphore)
                       (raise exception)))
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
   ident-fn     - a function of a request returning an opaque identifier by which to identify the
                  rate limiter. defaults to a global limit (shared by all clients) but you may set it to
                  ring-firewall-middleware.core/default-client-ident to implement a per-ip limit
                  instead or else write your own function to set it to some other group of clients
                  like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-rate-limit handler {}))
  ([handler {:keys [max-requests period deny-handler ident-fn]
             :or   {max-requests 100
                    period       60000
                    ident-fn     (constantly :world)
                    deny-handler default-limited-handler}}]
   (let [striped (coord/weak-leaky-semaphore-factory max-requests period)]
     (fn rate-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (if (.tryAcquire semaphore)
            (handler request)
            (deny-handler request))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (striped ident)]
          (if (.tryAcquire semaphore)
            (handler request respond raise)
            (deny-handler request respond raise))))))))


(defn wrap-knock-knock
  "Protects a ring handler against access until a secret knock is presented.
   After the secret knock is satisfied access is granted for a configurable
   amount of time to the client that presented the knock. Too many attempts
   of the wrong knock will land you on the ban list for a longer period of
   time and even correct knocks will be rejected."
  ([handler {:keys [secret max-attempts access-period ban-period deny-handler]
             :or   {secret        (str (UUID/randomUUID))
                    max-attempts  5
                    access-period 1800000                   ; 30 minutes
                    ban-period    86400000                  ; 1 day
                    deny-handler  default-forbidden-handler}}]
   (let [state (atom {:allow-list #{} :deny-list #{} :demerits {}})]
     (letfn [(successful-knock? [request]
               (let [param (util/query-param request "knock")]
                 (and (some? param) (util/secure= param secret))))
             (unsuccessful-knock? [request]
               (let [param (util/query-param request "knock")]
                 (and (some? param) (not (util/secure= param secret)))))
             (grant-access [state client-chain]
               (-> state
                   (update :allow-list conj client-chain)
                   (update :demerits dissoc client-chain)))
             (deny-access [state client-chain]
               (let [demerit-count (inc (or (get-in state [:demerits client-chain]) 0))]
                 (if (<= max-attempts demerit-count)
                   (-> state
                       (update :demerits dissoc client-chain)
                       (update :deny-list conj client-chain))
                   (-> state
                       (update :demerits assoc client-chain demerit-count)))))
             (banned? [old-state new-state client-chain]
               (and (contains? (:deny-list new-state) client-chain)
                    (not (contains? (:deny-list old-state) client-chain))))
             (allow! [client-chain]
               (swap! state grant-access client-chain)
               (timer/schedule (+ (System/currentTimeMillis) access-period)
                 (fn [] (swap! state update :allow-list disj client-chain))))
             (deny! [client-chain]
               (let [[old-state new-state] (swap-vals! state deny-access client-chain)]
                 (when (banned? old-state new-state client-chain)
                   (timer/schedule (+ (System/currentTimeMillis) ban-period)
                     (fn [] (swap! state update :deny-list disj client-chain))))))]
       (fn knock-knock-handler
         ([request]
          (let [{:keys [allow-list deny-list]} (deref state)
                client-chain (cidr/client-ip-chain request)]
            (cond
              (cidr/client-denied? client-chain deny-list)
              (deny-handler request)
              (cidr/client-allowed? client-chain allow-list)
              (handler request)
              (successful-knock? request)
              (do (allow! client-chain) (handler request))
              (unsuccessful-knock? request)
              (do (deny! client-chain) (deny-handler request))
              :otherwise
              (deny-handler request))))
         ([request respond raise]
          (let [{:keys [allow-list deny-list]} (deref state)
                client-chain (cidr/client-ip-chain request)]
            (cond
              (cidr/client-denied? client-chain deny-list)
              (deny-handler request respond raise)
              (cidr/client-allowed? client-chain allow-list)
              (handler request respond raise)
              (successful-knock? request)
              (do (allow! client-chain) (handler request respond raise))
              (unsuccessful-knock? request)
              (do (deny! client-chain) (deny-handler request respond raise))
              :otherwise
              (deny-handler request respond raise)))))))))