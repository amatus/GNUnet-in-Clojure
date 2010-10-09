(ns org.gnu.clojure.gnunet.util)

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
