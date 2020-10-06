(ns ring-firewall-middleware.core-test
  (:require [clojure.test :refer :all]
            [ring-firewall-middleware.core :as rfm]))

(def v6-range "fe80::21f:5bff:fe33:bd68")
(def v4-range "192.168.1.104")

(deftest in-cidr-range?-tests
  (testing "identical always matches"
    (is (rfm/in-cidr-range? v6-range v6-range))
    (is (rfm/in-cidr-range? v4-range v4-range)))
  (testing "ipv4 and ipv6 are mutually exclusive"
    (is (not (rfm/in-cidr-range? v6-range v4-range)))
    (is (not (rfm/in-cidr-range? v4-range v6-range))))
  (testing "0 mask"
    (is (rfm/in-cidr-range? "0.0.0.0/0" "123.4.5.6"))
    (is (rfm/in-cidr-range? "0.0.0.0/0" "192.168.0.159"))
    (is (rfm/in-cidr-range? "192.168.0.159/0" "123.4.5.6"))
    (is (rfm/in-cidr-range? "192.168.0.159/0" "192.168.0.159")))
  (testing "ipv4 range"
    (is (rfm/in-cidr-range? "192.168.1.0/24" "192.168.1.104"))
    (is (not (rfm/in-cidr-range? "192.168.1.128/25" "192.168.1.104")))
    (is (rfm/in-cidr-range? "192.168.1.128/25" "192.168.1.159"))
    (is (not (rfm/in-cidr-range? "192.168.1.128/25" "192.168.2.000"))))
  (testing "ipv6 range"
    (is (rfm/in-cidr-range? "2001:DB8::/48" "2001:DB8:0:0:0:0:0:0"))
    (is (rfm/in-cidr-range? "2001:DB8::/48" "2001:DB8:0:0:0:0:0:1"))
    (is (rfm/in-cidr-range? "2001:DB8::/48" "2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF"))
    (is (not (rfm/in-cidr-range? "2001:DB8::/48" "2001:DB8:1:0:0:0:0:0")))))


(deftest wrap-allow-ips-test
  (let [handler   (fn [req] {:status 200 :body "You have access!"})
        protected (rfm/wrap-allow-ips handler {:allow-list ["10.0.0.0/8"]})]
    (testing "remote-addr only"
      (is (= 200 (:status (protected {:remote-addr "10.20.206.46"}))))
      (is (= 403 (:status (protected {:remote-addr "192.1.1.1"})))))
    (testing "remote and forwarded"
      (is (= 200 (:status (protected {:headers     {"x-forwarded-for" "10.20.205.24"}
                                      :remote-addr "10.20.206.46"}))))
      (is (= 403 (:status (protected {:headers     {"x-forwarded-for" "10.20.205.24,192.10.1.1"}
                                      :remote-addr "10.20.206.46"})))))))

(deftest wrap-blocking-concurrency-limit-test
  (let [handler   (fn [req] (Thread/sleep 1000) {:status 200 :body "Response!"})
        protected (rfm/wrap-concurrency-throttle handler {:max-concurrent 1})
        start     (System/currentTimeMillis)
        one       (future (protected {}))
        two       (future (protected {}))]
    (deref one)
    (deref two)
    (is (<= 2000 (- (System/currentTimeMillis) start)))))


(deftest wrap-rejecting-concurrency-limit-test
  (let [handler   (fn [req] (Thread/sleep 1000) {:status 200 :body "Response!"})
        protected (rfm/wrap-concurrency-limit handler {:max-concurrent 1})
        one       (future (protected {}))
        two       (future (protected {}))
        responses [(deref one) (deref two)]]
    (is (not-empty (filter #(= 429 (:status %)) responses)))
    (is (not-empty (filter #(= 200 (:status %)) responses)))))
