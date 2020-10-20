(ns ring-firewall-middleware.core-test
  (:require [clojure.test :refer :all]
            [ring-firewall-middleware.core :refer :all]))


(deftest wrap-allow-ips-test
  (let [handler   (fn [req] {:status 200 :body "You have access!"})
        protected (wrap-allow-ips handler {:allow-list ["10.0.0.0/8"]})]
    (testing "remote-addr only"
      (is (= 200 (:status (protected {:remote-addr "10.20.206.46"}))))
      (is (= 403 (:status (protected {:remote-addr "192.1.1.1"})))))
    (testing "remote and forwarded"
      (is (= 200 (:status (protected {:headers     {"x-forwarded-for" "10.20.205.24"}
                                      :remote-addr "10.20.206.46"}))))
      (is (= 403 (:status (protected {:headers     {"x-forwarded-for" "10.20.205.24,192.10.1.1"}
                                      :remote-addr "10.20.206.46"})))))))

(deftest wrap-deny-ips-test
  (let [handler   (fn [req] {:status 200 :body "You have access!"})
        protected (wrap-deny-ips handler {:deny-list ["10.0.0.0/8"]})]
    (testing "remote-addr only"
      (is (= 403 (:status (protected {:remote-addr "10.20.206.46"}))))
      (is (= 200 (:status (protected {:remote-addr "192.1.1.1"})))))

    (testing "remote and forwarded"
      (is (= 200 (:status (protected {:headers     {"x-forwarded-for" "192.1.1.2"}
                                      :remote-addr "192.1.1.1"}))))
      (is (= 403 (:status (protected {:headers     {"x-forwarded-for" "10.20.205.24,192.10.1.2"}
                                      :remote-addr "192.1.1.1"})))))))

(deftest wrap-blocking-concurrency-limit-test
  (let [handler   (fn [req] (Thread/sleep 1000) {:status 200 :body "Response!"})
        protected (wrap-concurrency-throttle handler {:max-concurrent 1})
        start     (System/currentTimeMillis)
        one       (future (protected {}))
        two       (future (protected {}))]
    (deref one)
    (deref two)
    (is (<= 2000 (- (System/currentTimeMillis) start)))))

(deftest wrap-rejecting-concurrency-limit-test
  (let [handler   (fn [req] (Thread/sleep 1000) {:status 200 :body "Response!"})
        protected (wrap-concurrency-limit handler {:max-concurrent 1})
        one       (future (protected {}))
        two       (future (protected {}))
        responses [(deref one) (deref two)]]
    (is (not-empty (filter #(= 429 (:status %)) responses)))
    (is (not-empty (filter #(= 200 (:status %)) responses)))))


(deftest wrap-maintenance-mode-test
  (let [handler   (fn [request]
                    (when (number? request)
                      (Thread/sleep request))
                    {:status 200 :body "Under the hood"})
        protected (wrap-maintenance-limit handler)
        started   (promise)
        finished  (promise)]
    (is (= 200 (:status (protected {}))))
    (future
      (with-maintenance-mode :world
        (deliver started true)
        (Thread/sleep 2000))
      (deliver finished true))
    (deref started)
    (is (= 503 (:status (protected {}))))
    (deref finished)
    (is (= 200 (:status (protected {}))))))
