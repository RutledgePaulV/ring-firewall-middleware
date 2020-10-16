(ns ring-firewall-middleware.cidr-test
  (:require [clojure.test :refer :all]
            [ring-firewall-middleware.cidr :refer :all]))

(def v6-range "fe80::21f:5bff:fe33:bd68")
(def v4-range "192.168.1.104")

(deftest in-cidr-range?-tests
  (testing "identical always matches"
    (is (in-cidr-range? v6-range v6-range))
    (is (in-cidr-range? v4-range v4-range)))
  (testing "ipv4 and ipv6 are mutually exclusive"
    (is (not (in-cidr-range? v6-range v4-range)))
    (is (not (in-cidr-range? v4-range v6-range))))
  (testing "0 mask"
    (is (in-cidr-range? "0.0.0.0/0" "123.4.5.6"))
    (is (in-cidr-range? "0.0.0.0/0" "192.168.0.159"))
    (is (in-cidr-range? "192.168.0.159/0" "123.4.5.6"))
    (is (in-cidr-range? "192.168.0.159/0" "192.168.0.159")))
  (testing "ipv4 range"
    (is (in-cidr-range? "192.168.1.0/24" "192.168.1.104"))
    (is (not (in-cidr-range? "192.168.1.128/25" "192.168.1.104")))
    (is (in-cidr-range? "192.168.1.128/25" "192.168.1.159"))
    (is (not (in-cidr-range? "192.168.1.128/25" "192.168.2.000"))))
  (testing "ipv6 range"
    (is (in-cidr-range? "2001:DB8::/48" "2001:DB8:0:0:0:0:0:0"))
    (is (in-cidr-range? "2001:DB8::/48" "2001:DB8:0:0:0:0:0:1"))
    (is (in-cidr-range? "2001:DB8::/48" "2001:DB8:0:FFFF:FFFF:FFFF:FFFF:FFFF"))
    (is (not (in-cidr-range? "2001:DB8::/48" "2001:DB8:1:0:0:0:0:0")))))