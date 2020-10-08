(ns ring-firewall-middleware.impl
  (:import [clojure.lang ILookup IMeta IFn]
           [java.lang.ref WeakReference ReferenceQueue]
           [java.util.concurrent ConcurrentHashMap Semaphore DelayQueue Delayed TimeUnit]
           [java.util.function Function]))


(defn ^Function ->function [fun]
  (if (instance? Function fun)
    fun
    (reify Function (apply [this k] (fun k)))))

(defn weakly [queue x metadata]
  (proxy [WeakReference IMeta] [x queue]
    (meta [] metadata)))

(defn concurrent-weak-factory [fun]
  (let [ref-queue (ReferenceQueue.)
        container (ConcurrentHashMap.)
        gen       (->function (fn [k] (weakly ref-queue (fun k) {:key k})))]
    (reify ILookup
      (valAt [this key]
        (loop []
          (when-some [item (.poll ref-queue)]
            (.remove container (some-> item meta :key))
            (.clear item)
            (recur)))
        (.get ^WeakReference (.computeIfAbsent container key gen)))
      (valAt [this key not-found]
        (if-some [v (.valAt this key)] v not-found)))))

(defn weak-semaphore-factory
  "Returns a lookup table that dynamically allocates and returns
   semaphores for the same key but removes them from the table
   after no strong references to the semaphore remain"
  [permits]
  (concurrent-weak-factory (fn [k] (Semaphore. (int permits)))))


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
            "ring-firewall-middleware.impl/timer")
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
                (if (< (.availablePermits semaphore) n)
                  (let [expire-task (TimeoutTask. expire 0)]
                    (.remove task-queue expire-task)
                    (.release semaphore))
                  (let [expire-task (TimeoutTask. expire (+ timestamp period))]
                    (.put task-queue expire-task)))))]
      (force timer)
      (release)
      semaphore)))

(defn weak-leaky-semaphore-factory [max-requests period]
  (concurrent-weak-factory (fn [_] (make-limiter max-requests period))))