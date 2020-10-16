(ns ring-firewall-middleware.timer
  (:import [java.util.concurrent DelayQueue Delayed TimeUnit]
           [clojure.lang IFn]))

(defonce task-queue (DelayQueue.))

(defn process-queue! []
  (loop []
    (when-some [task (.take task-queue)]
      (try
        (task)
        (catch Exception e
          (.printStackTrace e)))
      (recur))))

(defonce timer
  (delay
    (doto (Thread. ^Runnable process-queue!)
      (.setName "ring-firewall-middleware/timer")
      (.setDaemon true)
      (.start))))

(deftype TimeoutTask [^IFn fun ^long timestamp]
  Delayed
  (getDelay [this time-unit]
    (let [remainder (- timestamp (System/currentTimeMillis))]
      (.convert time-unit remainder TimeUnit/MILLISECONDS)))
  (compareTo
    [this other]
    (let [ostamp (.-timestamp ^TimeoutTask other)]
      (if (< timestamp ostamp) -1 (if (= timestamp ostamp) 0 1))))
  IFn
  (invoke [this] (fun))
  Object
  (hashCode [this]
    (.hashCode fun))
  (equals [this that]
    (identical? (.-fun this) (.-fun ^TimeoutTask that))))

(defn schedule [timestamp fun]
  (force timer)
  (let [task (TimeoutTask. fun timestamp)]
    (.put task-queue task)))

(defn unschedule [fun]
  (let [task (TimeoutTask. fun 0)]
    (.remove task-queue task)))