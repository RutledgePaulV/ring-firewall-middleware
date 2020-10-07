(ns ring-firewall-middleware.limiters-test
  (:require [clojure.test :refer :all])
  (:require [ring-firewall-middleware.limiters :refer :all])
  (:import [java.util.concurrent Semaphore]
           [java.util UUID]))

(deftest striped-limiter-test
  (testing "exceeded rate limit results in denied semaphore acquire"
    (let [striped   (striped-limiter 10 1000)
          uuid      (UUID/randomUUID)
          semaphore ^Semaphore (.get striped uuid)]
      (dotimes [_ 10]
        (is (.tryAcquire semaphore)))
      (is (not (.tryAcquire semaphore)))
      (Thread/sleep 1100)
      (dotimes [_ 10]
        (is (.tryAcquire semaphore)))
      (is (not (.tryAcquire semaphore)))
      (Thread/sleep 3000)
      (is (zero? (.size task-queue)))))

  (testing "obeyed rate limit results in endless acquires"
    (let [striped   (striped-limiter 50 1000)
          uuid      (UUID/randomUUID)
          semaphore ^Semaphore (.get striped uuid)]
      (dotimes [_ 100]
        (is (.tryAcquire semaphore))
        (Thread/sleep 30)))))
