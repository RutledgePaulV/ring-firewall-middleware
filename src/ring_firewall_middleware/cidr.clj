(ns ring-firewall-middleware.cidr
  (:require [clojure.string :as strings]
            [ring-firewall-middleware.utils :as util])
  (:import [java.net InetAddress]))


(def public-ipv4-subnets
  #{"0.0.0.0/5"
    "8.0.0.0/7"
    "11.0.0.0/8"
    "12.0.0.0/6"
    "16.0.0.0/4"
    "32.0.0.0/3"
    "64.0.0.0/2"
    "128.0.0.0/3"
    "160.0.0.0/5"
    "168.0.0.0/6"
    "172.0.0.0/12"
    "172.32.0.0/11"
    "172.64.0.0/10"
    "172.128.0.0/9"
    "173.0.0.0/8"
    "174.0.0.0/7"
    "176.0.0.0/4"
    "192.0.0.0/9"
    "192.128.0.0/11"
    "192.160.0.0/13"
    "192.169.0.0/16"
    "192.170.0.0/15"
    "192.172.0.0/14"
    "192.176.0.0/12"
    "192.192.0.0/10"
    "193.0.0.0/8"
    "194.0.0.0/7"
    "196.0.0.0/6"
    "200.0.0.0/5"
    "208.0.0.0/4"})

(def public-ipv6-subnets
  #{"0:0:0:0:0:0:0:0/1"
    "8000:0:0:0:0:0:0:0/2"
    "c000:0:0:0:0:0:0:0/3"
    "e000:0:0:0:0:0:0:0/4"
    "f000:0:0:0:0:0:0:0/5"
    "f800:0:0:0:0:0:0:0/6"
    "fe00:0:0:0:0:0:0:0/7"})

(def private-ipv4-subnets
  #{"10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"})

(def private-ipv6-subnets
  #{"fc00::/7"})

(def private-subnets
  (into private-ipv4-subnets private-ipv6-subnets))

(def public-subnets
  (into public-ipv4-subnets public-ipv6-subnets))

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
  (or (contains? (set cidr-ranges) ip-address)
      (reduce #(if (in-cidr-range? %2 ip-address) (reduced true) false) false cidr-ranges)))

(defn private-address?
  "Is this a private ip address as defined by RFC 1918 or RFC 4193?"
  [ip-address]
  (in-cidr-ranges? private-subnets ip-address))

(defn public-address?
  "Is this not a private ip address as defined by RFC 1918 or RFC 4193?"
  [ip-address]
  (in-cidr-ranges? public-subnets ip-address))

(defn client-ip-chain
  "Gets the set of IPs involved in the http request headers and source network packet."
  [request]
  (into #{(:remote-addr request)} (util/get-forwarded-ip-addresses request)))

(defn client-allowed?
  "Does the ring request satisfy the allow list? For a request to be allowed
   every ip address in the http header chain needs to be allowed."
  [client-chain allow-list]
  (let [allow-list (util/touch allow-list)
        predicate  (partial in-cidr-ranges? (set (filter string? allow-list)))]
    (or (contains? (set allow-list) client-chain) (every? predicate client-chain))))

(defn client-denied?
  "Does the ring request satisfy the deny list? For a request to be denied
   just one ip address in the http header chain needs to be denied."
  [client-chain deny-list]
  (let [deny-list (util/touch deny-list)
        predicate (partial in-cidr-ranges? (set (filter string? deny-list)))]
    (or (contains? (set deny-list) client-chain) (not (empty? (filter predicate client-chain))))))