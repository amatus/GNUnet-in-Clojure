(ns org.gnu.clojure.gnunet.util)

(defmacro assert-args [fnname & pairs]
  `(do (when-not ~(first pairs)
         (throw (IllegalArgumentException.
                  ~(str fnname " requires " (second pairs)))))
     ~(let [more (nnext pairs)]
        (when more
          (list* `assert-args fnname more)))))

(defn queue-seq!
  "Returns a lazy seq that consumes a
  java.util.concurrent.ConcurrentLinkedQueue."
  [queue]
  (lazy-seq (when-let [c (.poll queue)] (cons c (queue-seq! queue)))))

(defn buffer-seq!
  "Returns a lazy seq that consumes a subclass of java.nio.Buffer."
  [buffer]
  (lazy-seq (when (.hasRemaining buffer)
              (cons (.get buffer) (buffer-seq! buffer)))))

(defn my-max
  "Returns the maximum in a collection of comparable values."
  [& coll]
  (last (sort coll)))

(defn available-processors
  "Returns the number of processors available to this Java runtime."
  []
  (.availableProcessors (Runtime/getRuntime)))

(defn skip
  "Takes any number of arguments and returns nil."
  [& _])

(defn assoc-deep
  "Associates val with the 'path' of keys in a nested map."
  [_map _val _key & _keys]
  (if (nil? _keys)
    (assoc _map _key _val)
    (assoc _map _key (apply assoc-deep (_map _key) _val _keys))))

(defn conj-vals
  [_map zero kvs]
  (reduce 
    (fn [_map kv]
      (let [_key (first kv)
            old-val (_map _key zero)]
        (assoc _map _key 
               (conj old-val (second kv)))))
        _map (partition 2 kvs)))

(defn do-callbacks!
  [callback-seq & args]
  (doseq [callback! callback-seq]
    (apply callback! args)))
