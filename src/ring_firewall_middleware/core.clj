(ns ring-firewall-middleware.core
  (:require [clojure.string :as strings]
            [ring-firewall-middleware.impl :as impl])
  (:import [java.net InetAddress]
           [clojure.lang IDeref]
           [java.util.concurrent Semaphore]))

(def public-ipv4-subnets
  (sorted-set
    "0.0.0.0/5" "8.0.0.0/7" "11.0.0.0/8"
    "12.0.0.0/6" "16.0.0.0/4" "32.0.0.0/3"
    "64.0.0.0/2" "128.0.0.0/3" "160.0.0.0/5"
    "168.0.0.0/6" "172.0.0.0/12" "172.32.0.0/11"
    "172.64.0.0/10" "172.128.0.0/9" "173.0.0.0/8"
    "174.0.0.0/7" "176.0.0.0/4" "192.0.0.0/9"
    "192.128.0.0/11" "192.160.0.0/13" "192.169.0.0/16"
    "192.170.0.0/15" "192.172.0.0/14" "192.176.0.0/12"
    "192.192.0.0/10" "193.0.0.0/8" "194.0.0.0/7"
    "196.0.0.0/6" "200.0.0.0/5" "208.0.0.0/4"))

(def public-ipv6-subnets
  (sorted-set
    "0:0:0:0:0:0:0:0/1" "8000:0:0:0:0:0:0:0/2"
    "c000:0:0:0:0:0:0:0/3" "e000:0:0:0:0:0:0:0/4"
    "f000:0:0:0:0:0:0:0/5" "f800:0:0:0:0:0:0:0/6"
    "fe00:0:0:0:0:0:0:0/7"))

(def private-ipv4-subnets
  (sorted-set "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"))

(def private-ipv6-subnets
  (sorted-set "fc00::/7"))

(def private-subnets
  (into private-ipv4-subnets private-ipv6-subnets))

(def public-subnets
  (into public-ipv4-subnets public-ipv6-subnets))

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
  (in-cidr-ranges? public-subnets ip-address))

(defn default-deny-handler
  "Provides a default ring response for users who didn't meet the firewall requirements."
  ([request]
   {:status  403
    :headers {"Content-Type" "text/plain"}
    :body    "Access denied"})
  ([request respond raise]
   (respond (default-deny-handler request))))

(defn default-deny-limit-handler
  "Provides a default ring response for users who didn't meet the firewall requirements."
  ([request]
   {:status  429
    :headers {"Content-Type" "text/plain"}
    :body    "Request limit exceeded"})
  ([request respond raise]
   (respond (default-deny-limit-handler request))))

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
   ranges cover the entire internal network space as defined by RFC 1918 and RFC 4193.

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
   any forbidden clients / proxy servers. The default deny-list ranges cover the entire internal
   public network space.

   deny-list    - cidr ranges collection that, if matched, will result in a denied request. optionally
                  provide a ref type in which case it will be dereferenced before use.

   deny-handler - a function of a ring request that returns a ring response in the event of a denied request.

   "
  ([handler]
   (wrap-deny-ips handler {}))
  ([handler {:keys [deny-list deny-handler]
             :or   {deny-list    public-subnets
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
   (let [stripe (impl/weak-semaphore-factory max-concurrent)]
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
                    deny-handler   default-deny-limit-handler
                    ident-fn       (constantly :world)}}]
   (let [stripe (impl/weak-semaphore-factory max-concurrent)]
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
   (let [striped (impl/weak-leaky-semaphore-factory max-requests period)]
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
                    deny-handler default-deny-limit-handler}}]
   (let [striped (impl/weak-leaky-semaphore-factory max-requests period)]
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