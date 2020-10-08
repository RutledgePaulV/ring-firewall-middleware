(ns ring-firewall-middleware.impl-test
  (:require [clojure.test :refer :all])
  (:require [ring-firewall-middleware.impl :refer :all])
  (:import [java.util.concurrent Semaphore]
           [java.util UUID]))

(deftest weak-leaky-semaphore-factory-test
  (testing "exceeded rate limit results in denied semaphore acquire"
    (let [striped   (weak-leaky-semaphore-factory 10 1000)
          uuid      (UUID/randomUUID)
          semaphore ^Semaphore (get striped uuid)]
      (dotimes [_ 10]
        (is (.tryAcquire semaphore)))
      (is (not (.tryAcquire semaphore)))
      (Thread/sleep 1100)
      (dotimes [_ 10]
        (is (.tryAcquire semaphore)))
      (is (not (.tryAcquire semaphore)))
      (Thread/sleep 4000)
      (is (zero? (.size task-queue)))))

  (testing "obeyed rate limit results in endless acquires"
    (let [striped   (weak-leaky-semaphore-factory 50 1000)
          uuid      (UUID/randomUUID)
          semaphore ^Semaphore (get striped uuid)]
      (dotimes [_ 100]
        (is (.tryAcquire semaphore))
        (Thread/sleep 30)))))
