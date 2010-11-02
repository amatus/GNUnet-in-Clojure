(ns org.gnu.clojure.gnunet.bloomfilter
  (:use (org.gnu.clojure.gnunet message parser)
    clojure.contrib.monads))

(def bloomfilter-k 16)

(defn make-bloomfilter
  [bitmap size k]
  {:bitmap bitmap
   :size size
   :k k})

(defn parse-bloomfilter
  [k]
  (domonad parser-m
    [bitmap (one-or-more item)
     :let [size (count bitmap)]
     :when (== 0 (bit-and size (dec size)))]
    (make-bloomfilter (decode-uint bitmap) size k)))