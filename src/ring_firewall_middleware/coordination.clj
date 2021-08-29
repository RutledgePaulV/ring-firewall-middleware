(ns ring-firewall-middleware.coordination
  (:require [ring-firewall-middleware.timer :as timer])
  (:import [clojure.lang IMeta]
           [java.lang.ref WeakReference ReferenceQueue]
           [java.util.concurrent ConcurrentHashMap Semaphore]
           [java.util.function Function]
           (java.util.concurrent.locks ReentrantReadWriteLock)))

(defn weakly-memoize
  ([f] (weakly-memoize f identity))
  ([f cache-key-fn]
   (let [ref-queue (ReferenceQueue.)
         container (ConcurrentHashMap.)]
     (fn [& args]
       (let [cache-key (cache-key-fn (vec args))
             generator (reify Function
                         (apply [this cache-key]
                           (let [x (apply f args)]
                             (loop []
                               (when-some [item (.poll ref-queue)]
                                 (.remove container (some-> item meta :key))
                                 (recur)))
                             (proxy [WeakReference IMeta] [x ref-queue]
                               (meta [] {:key cache-key})))))
             ref       (.computeIfAbsent container cache-key generator)]
         (.get ^WeakReference ref))))))

(defn weak-semaphore-factory [permits]
  (weakly-memoize (fn [_] (Semaphore. (int permits) true))))

(defn leaky-semaphore [permits period]
  (let [semaphore (Semaphore. permits true)
        frequency (quot period permits)]
    (letfn [(release []
              (let [timestamp (System/currentTimeMillis)]
                (timer/schedule (+ timestamp frequency) release)
                (if (< (.availablePermits semaphore) permits)
                  (do (timer/unschedule expire) (.release semaphore))
                  (timer/schedule (+ timestamp period) expire))))
            (expire [] (timer/unschedule release))]
      (release)
      semaphore)))

(defn weak-leaky-semaphore-factory [max-requests period]
  (weakly-memoize (fn [_] (leaky-semaphore max-requests period))))

(defn weak-read-write-factory []
  (weakly-memoize (fn [_] (ReentrantReadWriteLock.))))