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
  [map val key & keys]
  (if (nil? keys)
    (assoc map key val)
    (assoc map key (apply assoc-deep (map key) val keys))))
