(ns org.gnu.clojure.gnunet.util)

(defmacro assert-args [fnname & pairs]
  `(do (when-not ~(first pairs)
         (throw (IllegalArgumentException.
                  ~(str fnname " requires " (second pairs)))))
     ~(let [more (nnext pairs)]
        (when more
          (list* `assert-args fnname more)))))

(defn queue-seq!
  "Consume a queue and present it as a sequence."
  [queue]
  (lazy-seq (when-let [c (.poll queue)] (cons c (queue-seq! queue)))))

(defn buffer-seq!
  [buffer]
  (lazy-seq (when (.hasRemaining buffer)
              (cons (.get buffer) (buffer-seq! buffer)))))

(defn my-max
  "Return the maximum in a collection of comparable values."
  [& coll]
  (last (sort coll)))

(defn available-processors
  []
  (.availableProcessors (Runtime/getRuntime)))
