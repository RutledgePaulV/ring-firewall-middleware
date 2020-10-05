(ns ring-firewall-middleware.core
  (:require [clojure.string :as strings])
  (:import [java.net InetAddress]
           [clojure.lang IDeref]
           [java.util.concurrent Semaphore]
           [com.google.common.util.concurrent Striped]))

(def rfc1918-private-subnets
  ["10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"])

(def rfc4193-private-subnets
  ["fc00::/7"])

(def private-subnets
  (into rfc1918-private-subnets rfc4193-private-subnets))

(def honored-proxy-headers
  ["True-Client-IP" "true-client-ip" "X-Forwarded-For" "x-forwarded-for"])

(defn in-cidr-range?
  "Is a given client ip within a given cidr range?"
  [cidr client-ip]
  (try
    (let [[cidr-ip cidr-mask]
          (if (strings/includes? cidr "/")
            (let [[ip mask] (strings/split cidr #"/")]
              [ip (Integer/parseInt mask)])
            [cidr (int -1)])
          cidr-inet   (InetAddress/getByName cidr-ip)
          client-inet (InetAddress/getByName client-ip)]
      (and
        (identical? (class cidr-inet) (class client-inet))
        (if (neg? cidr-mask)
          (= cidr-inet client-inet)
          (let [cidr-bytes      (.getAddress cidr-inet)
                client-bytes    (.getAddress client-inet)
                cidr-mask-bytes (quot cidr-mask (int 8))
                final-byte      (unchecked-byte (bit-shift-right 0xFF00 (bit-and cidr-mask 0x07)))]
            (and
              (reduce #(or (= (aget cidr-bytes %2) (aget client-bytes %2)) (reduced false)) true (range cidr-mask-bytes))
              (or (zero? final-byte)
                  (= (bit-and (aget cidr-bytes cidr-mask-bytes) final-byte)
                     (bit-and (aget client-bytes cidr-mask-bytes) final-byte))))))))
    (catch Exception e false)))

(defn in-cidr-ranges?
  "Is a given ip address in one of the provided cidr ranges?"
  [cidr-ranges ip-address]
  (reduce #(if (in-cidr-range? %2 ip-address) (reduced true) false) false cidr-ranges))

(defn private-address?
  "Is this a private ip address as defined by RFC 1918 or RFC 4193?"
  [ip-address]
  (in-cidr-ranges? private-subnets ip-address))

(defn public-address?
  "Is this not a private ip address as defined by RFC 1918 or RFC 4193?"
  [ip-address]
  (not (private-address? ip-address)))

(defn default-deny-handler
  "Provides a default ring response for users who didn't meet the firewall requirements."
  ([request]
   {:status  403
    :headers {"Content-Type" "text/plain"}
    :body    "Access denied"})
  ([request respond raise]
   (respond (default-deny-handler request))))

(defn default-deny-rate-limit-handler
  "Provides a default ring response for users who didn't meet the firewall requirements."
  ([request]
   {:status  429
    :headers {"Content-Type" "text/plain"}
    :body    "Request limit exceeded"})
  ([request respond raise]
   (respond (default-deny-rate-limit-handler request))))

(defn get-forwarded-ip-addresses
  "Gets all the forwarded ip addresses from a request."
  [request]
  (letfn [(parse-header [header]
            (if-some [value (get-in request [:headers header])]
              (strings/split value #"\s*,\s*")
              ()))]
    (->> honored-proxy-headers
         (mapcat parse-header)
         (remove strings/blank?))))

(defn default-client-ident [request]
  (into #{(:remote-addr request)} (get-forwarded-ip-addresses request)))

(defn request-matches?
  "Does the ring request satisfy the access list?"
  [request access-list]
  (->> (default-client-ident request)
       (every? (partial in-cidr-ranges? access-list))))


(defn- touch [x]
  (if (instance? IDeref x) (deref x) x))


(defn wrap-allow-ips
  "Protect a ring handler with source ip authentication. Your allow-list ranges must cover
   any permitted clients as well as any intermediate proxy servers. The default allow-list
   ranges are the entire internal network space as defined by RFC 1918 and RFC 4193.

   allow-list    - cidr ranges collection that, if matched, will result in an allowed request. optionally
                  provide a ref type in which case it will be dereferenced before use.

   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.

   "
  ([handler]
   (wrap-allow-ips handler {}))
  ([handler {:keys [allow-list deny-handler]
             :or   {allow-list   private-subnets
                    deny-handler default-deny-handler}}]
   (fn allow-ips-handler
     ([request]
      (if (request-matches? request (touch allow-list))
        (handler request)
        (deny-handler request)))
     ([request respond raise]
      (if (request-matches? request (touch allow-list))
        (handler request respond raise)
        (deny-handler request respond raise))))))


(defn wrap-deny-ips
  "Protect a ring handler with source ip authentication. Your deny-list ranges must cover
   any forbidden clients / proxy servers. The default deny-list ranges are the entire internal
   network space as defined by RFC 1918 and RFC 4193.

   deny-list    - cidr ranges collection that, if matched, will result in a denied request. optionally
                  provide a ref type in which case it will be dereferenced before use.

   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.

   "
  ([handler]
   (wrap-deny-ips handler {}))
  ([handler {:keys [deny-list deny-handler]
             :or   {deny-list    private-subnets
                    deny-handler default-deny-handler}}]
   (fn deny-ips-handler
     ([request]
      (if-not (request-matches? request (touch deny-list))
        (handler request)
        (deny-handler request)))
     ([request respond raise]
      (if-not (request-matches? request (touch deny-list))
        (handler request respond raise)
        (deny-handler request respond raise))))))


(defn wrap-concurrency-throttle
  "Protect a ring handler against excessive concurrency. New requests
   after the concurrency limit is already saturated will block until
   a slot is available.

   max-concurrent - the maximum number of requests to be handled concurrently
   ident-fn       - a function of a request returning an opaque identifier by which to identify the limited
                    semaphore. defaults to a global limit (shared by all users) but you may set it to
                    ring-firewall-middleware.core/default-client-ident to implement a per-user limit
                    instead or else right your own function to set it to some other group of clients
                    like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-concurrency-throttle handler {}))
  ([handler {:keys [max-concurrent ident-fn]
             :or   {max-concurrent 200
                    ident-fn       (constantly :world)}}]
   (let [table (Striped/lazyWeakSemaphore 1 max-concurrent)]
     (fn blocking-concurrency-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (.get table ident)]
          (try
            (.acquire semaphore)
            (handler request)
            (finally
              (.release semaphore)))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (.get table ident)]
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
   ident-fn       - a function of a request returning an opaque identifier by which to identify the limited
                    semaphore. defaults to a global limit (shared by all users) but you may set it to
                    ring-firewall-middleware.core/default-client-ident to implement a per-user limit
                    instead or else right your own function to set it to some other group of clients
                    like those representing one (of many) tenants.
   "
  ([handler]
   (wrap-concurrency-limit handler {}))
  ([handler {:keys [max-concurrent deny-handler ident-fn]
             :or   {max-concurrent 200
                    deny-handler   default-deny-rate-limit-handler
                    ident-fn       (constantly :world)}}]
   (let [table (Striped/lazyWeakSemaphore 1 max-concurrent)]
     (fn rejecting-concurrency-limit-handler
       ([request]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (.get table ident)]
          (if (.tryAcquire semaphore)
            (try (handler request)
                 (finally (.release semaphore)))
            (deny-handler request))))
       ([request respond raise]
        (let [ident     (ident-fn request)
              semaphore ^Semaphore (.get table ident)]
          (if (.tryAcquire semaphore)
            (handler request
                     (fn [response]
                       (.release semaphore)
                       (respond response))
                     (fn [exception]
                       (.release semaphore)
                       (raise exception)))
            (deny-handler request respond raise))))))))
