(ns ring-firewall-middleware.maintenance
  "State for implementing a maintenance mode."
  (:import [java.util.concurrent Phaser]
           [java.util.function Supplier]))


; stores the lock (a promise) and phasers
(defonce STATE (atom {}))

; track whether the current thread has been registered with the phaser
(defonce registered?
  (ThreadLocal/withInitial
    (reify Supplier
      (get [this] false))))

(defn new-state []
  {:lock (doto (promise) (deliver true)) :phaser (Phaser.)})

(defn get-state [ident]
  (-> (swap! STATE update ident #(or % (new-state)))
      (get ident)))

(defn exclusive-lock
  "Returns a map of {:lock (promise) :phaser (Phaser.)}. It's expected
   that the thread that obtains the lock will first await on the phaser,
   then execute any exclusive necessary code, and"
  [ident]
  (let [[old new] (swap-vals! STATE update ident assoc :lock (promise))]
    (some-> old (get-in [ident :lock]) (deref))
    (get new ident)))

(defn release-lock [lock]
  (deliver lock true))

(defn register-phaser [phaser]
  (when-not (.get registered?)
    (.set registered? true)
    (.register phaser)))

(defn deregister-phaser [phaser]
  (when (.get registered?)
    (.arriveAndDeregister phaser)
    (.set registered? false)))

(defn await-phaser [phaser]
  (if-not (.get registered?)
    (.register ^Phaser phaser)
    (.set registered? false))
  (.arriveAndAwaitAdvance ^Phaser phaser))

