(ns ring-firewall-middleware.impl
  (:import [clojure.lang IMeta IFn]
           [java.lang.ref WeakReference ReferenceQueue]
           [java.util.concurrent ConcurrentHashMap Semaphore DelayQueue Delayed TimeUnit]
           [java.util.function Function]))

(defn weakly-memoize
  ([f] (weakly-memoize f identity))
  ([f cache-key-fn]
   (let [ref-queue (ReferenceQueue.)
         container (ConcurrentHashMap.)]
     (fn [& args]
       (let [cache-key (cache-key-fn (vec args))
             generator (reify Function
                         (apply [this cache-key]
                           (loop []
                             (when-some [item (.poll ref-queue)]
                               (.remove container (:key (meta item)))
                               (recur)))
                           (proxy [WeakReference IMeta]
                                  [(apply f args) ref-queue]
                             (meta [] {:key cache-key}))))
             ref       (.computeIfAbsent container cache-key generator)]
         (.get ^WeakReference ref))))))

(defn weak-semaphore-factory [permits]
  (weakly-memoize (fn [k] (Semaphore. (int permits)))))

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
  (weakly-memoize (fn [_] (make-limiter max-requests period))))