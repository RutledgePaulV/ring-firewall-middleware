(ns ring-firewall-middleware.core
  (:require [clojure.string :as strings])
  (:import [java.net InetAddress]
           [clojure.lang IDeref]
           [java.util.concurrent DelayQueue TimeUnit]))

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

(defn request-matches?
  "Does the ring request satisfy the access list?"
  [request access-list]
  (->> (get-forwarded-ip-addresses request)
       (into #{(:remote-addr request)})
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

(defn get-client-ip [request]
  (or (first (get-forwarded-ip-addresses request)) (:remote-addr request)))

(defn default-knock-function [request]
  (or (get-in request [:query-params :knock])
      (get-in request [:query-params "knock"])))

(defn parameter-knocking
  "Like port knocking, but for web requests. Make requests in the
   right order with the right values for the `knock` query parameter
   to get your ip address added to the allow-list for the endpoint.

   secret-knock - the sequence of values that must be submitted in the
                  right order to obtain access.

   "
  ([handler]
   (parameter-knocking handler {}))
  ([handler {:keys [secret-knock knock-fun deny-handler]
             :or   {knock-fun    default-knock-function
                    deny-handler default-deny-handler}}]
   (let [permitted  (atom #{})
         evaluating (atom {})
         firewalled (wrap-allow-ips handler {:allow-list permitted})]
     (letfn [(listen-for-knocks [request]
               (when-some [knock (default-knock-function request)]
                 (let [ips (into #{(:remote-addr request)} (get-forwarded-ip-addresses request))
                       new (swap! evaluating update ips
                                  (fn [knock-thus-far]
                                    (->> (cons knock (or knock-thus-far ()))
                                         (take (count secret-knock)))))]
                   (when (= (get new ips) secret-knock)
                     (swap! permitted (partial apply conj) ips)
                     (swap! evaluating dissoc ips)))))]
       (fn knocking-handler
         ([request] (listen-for-knocks request) (firewalled request))
         ([request respond raise] (listen-for-knocks request) (firewalled request respond raise)))))))


(defn wrap-ip-ban
  ([handler] (wrap-ip-ban handler {}))
  ([handler {:keys [demerits duration deny-handler]
             :or   {demerits     10
                    duration     60000
                    deny-handler default-deny-handler}}]
   (let [banned          (atom #{})
         reinstate-queue (DelayQueue.)
         reinstate-proc  (future
                           (loop []
                             (when-some [client-ip (.take reinstate-queue)]
                               (swap! banned disj client-ip)
                               (recur))))
         evaluating      (atom {})
         firewalled      (wrap-deny-ips handler {:deny-list banned})]
     (letfn [(rebuke [request]
               (let [client-ip (get-client-ip request)
                     updated   (swap! evaluating update client-ip (fnil inc 0))]
                 (when (<= demerits (get updated client-ip))
                   (let [[old new] (swap-vals! banned conj client-ip)]
                     (when (and (not (contains? old client-ip)) (contains? new client-ip))
                       (swap! evaluating dissoc client-ip)
                       (.offer reinstate-queue client-ip duration TimeUnit/MILLISECONDS))))))
             (offensive? [response]
               (contains? #{401 404} (:status response)))]
       (fn ip-ban-handler
         ([request]
          (try
            (let [response (firewalled request)]
              (when (offensive? response)
                (rebuke request))
              response)
            (catch Exception e
              (rebuke request)
              (throw e))))
         ([request respond raise]
          ([request]
           (firewalled
             request
             (fn [response]
               (when (offensive? response)
                 (rebuke request))
               (respond response))
             (fn [exception]
               (rebuke request)
               (raise exception))))))))))