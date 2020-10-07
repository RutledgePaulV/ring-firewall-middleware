(ns ring-firewall-middleware.limiters
  "Implements a leaky bucket rate limiter using semaphores and delay queues."
  (:import [java.util.concurrent Semaphore DelayQueue TimeUnit Delayed]
           [com.google.common.base Supplier]
           [com.google.common.util.concurrent Striped]
           [clojure.lang IFn]))


(defn custom-lazy-stripe [min-stripes fun]
  (let [parameters (into-array Class [Integer/TYPE Supplier])
        method     (doto (.getDeclaredMethod ^Class Striped "lazy" parameters)
                     (.setAccessible true))
        arguments  (into-array Object [(int min-stripes) (reify Supplier (get [this] (fun)))])]
    (.invoke method nil arguments)))

(defonce task-queue
  (DelayQueue.))

(defonce timer
  (delay
    (doto (Thread.
            ^Runnable
            (fn [] (loop []
                     (when-some [task (.take task-queue)]
                       (task))
                     (recur)))
            "ring-firewall-middleware-timer")
      (.setDaemon true)
      (.start))))

(deftype TimeoutTask [^IFn fun ^long timestamp]
  Delayed
  (getDelay [this time-unit]
    (let [remainder (- timestamp (System/currentTimeMillis))]
      (.convert time-unit remainder TimeUnit/MILLISECONDS)))
  (compareTo
    [this other]
    (let [ostamp (.timestamp ^TimeoutTask other)]
      (if (< timestamp ostamp)
        -1
        (if (= timestamp ostamp)
          0
          1))))
  IFn
  (invoke [this]
    (fun))
  Object
  (hashCode [this]
    (.hashCode fun))
  (equals [this that]
    (.equals (.fun this) (.fun ^TimeoutTask that))))

(defn make-limiter [n period]
  (let [semaphore (Semaphore. n true)
        frequency (quot period n)]
    (letfn [(expire []
              (let [task (TimeoutTask. release 0)]
                (.remove task-queue task)))
            (release []
              (let [timestamp    (System/currentTimeMillis)
                    release-task (TimeoutTask. release (+ timestamp frequency))]
                (.put task-queue release-task)
                (when (< (.availablePermits semaphore) n)
                  (.release semaphore)
                  ; shift the expire task because there's still activity
                  (let [expire-task (TimeoutTask. expire (+ timestamp period))]
                    (.remove task-queue expire-task)
                    (.put task-queue expire-task)))))]
      (force timer)
      (release)
      semaphore)))


(defn striped-limiter [max-requests period]
  (custom-lazy-stripe 1 #(make-limiter max-requests period)))