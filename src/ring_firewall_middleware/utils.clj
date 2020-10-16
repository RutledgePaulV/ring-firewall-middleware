(ns ring-firewall-middleware.utils
  (:require [clojure.string :as strings])
  (:import [java.net URLDecoder URLEncoder]
           [java.util.regex Pattern]
           [clojure.lang IDeref]
           [java.security MessageDigest]))

(defn get-forwarded-ip-addresses
  "Gets all the forwarded ip addresses from a request."
  [request]
  (letfn [(parse-header [header]
            (if-some [value (get-in request [:headers header])]
              (strings/split value #"\s*,\s*")
              ()))
          (strip-port [address]
            (strings/replace address #":\d*$" ""))]
    (->> ["x-forwarded-for" "X-Forwarded-For"]
         (mapcat parse-header)
         (remove strings/blank?)
         (mapv strip-port))))

(defn secure= [^String s1 ^String s2]
  (MessageDigest/isEqual (.getBytes (or s1 "")) (.getBytes (or s2 ""))))

(defn query-param [request param]
  (cond
    (not-empty (get-in request [:query-params]))
    (or (get-in request [:query-params (name param)])
        (get-in request [:query-params (keyword param)]))
    (not (strings/blank? (get-in request [:query-string])))
    (let [quoted  (Pattern/quote (URLEncoder/encode param "UTF-8"))
          pattern (Pattern/compile (format "%s=([^&]+)" quoted) Pattern/CASE_INSENSITIVE)]
      (when-some [[_ value] (re-find pattern (:query-string request))]
        (URLDecoder/decode value "UTF-8")))))

(defn touch [x]
  (if (instance? IDeref x) (deref x) x))