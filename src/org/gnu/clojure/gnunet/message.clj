(ns org.gnu.clojure.gnunet.message
  (:import java.math.BigInteger))

(defn bit-count-to-bytes [x] (quot (+ 7 x) 8))

(defn encode-int
  "Convert an integer to a sequence of bytes in network order."
  [x]
  (let [big (bigint x)
        len (max 1 (bit-count-to-bytes (.bitLength big)))
        a (.toByteArray big)]
    (drop (- (alength a) len) a)))

(defn encode-int16
  "Convert a 16-bit integer to a sequence of bytes in network order."
  [x]
  (list (byte (bit-shift-right x 8)) (byte (bit-and x 0xFF))))

(defn encode-int32
  "Convert a 32-bit integer to a sequence of bytes in network order."
  [x]
  (concat (encode-int16 (bit-shift-right x 16))
    (encode-int16 (bit-and x 0xFFFF))))

(defn encode-int64
  "Convert a 64-bit integer to a sequence of bytes in network order."
  [x]
  (concat (encode-int32 (bit-shift-right (bigint x) 32))
    (encode-int32 (bit-and x 0xFFFFFFFF))))

(defn decode-int
  "Convert a sequence of bytes in network order to a 2's complement integer."
  [a]
  (BigInteger. (byte-array a)))

(defn decode-uint
  "Convert a sequence of bytes in network order to an unsigned integer."
  [a]
  (BigInteger. 1 (byte-array a)))

(defn split-at-or-throw
  [n a]
  (let [[head tail] (split-at n a)]
    (if (not (== (count head) n))
      (throw (java.lang.Exception. "Not long enough.")))
    [head tail]))

(defn decode-uint16-and-split
  [a]
  (let [[encoded-int after-encoded-int] (split-at-or-throw 2 a)]
    [(int (decode-uint encoded-int)) after-encoded-int]))

(defn decode-uint32-and-split
  [a]
  (let [[encoded-int after-encoded-int] (split-at-or-throw 4 a)]
    [(int (decode-uint encoded-int)) after-encoded-int]))

(defn decode-uint64-and-split
  [a]
  (let [[encoded-int after-encoded-int] (split-at-or-throw 8 a)]
    [(long (decode-uint encoded-int)) after-encoded-int]))

(defn encode-header
  "Encode a gnunet message header."
  [hdr]
  (concat
    (encode-int16 (:size hdr))
    (encode-int16 (:message-type hdr))))

(def header-size (count (encode-header {:size 0 :message-type 0})))

(defn decode-header-and-split
  "Split a seq into a gnunet message header and the rest."
  [a]
  (let [[size after-size] (decode-uint16-and-split a)
        [message-type after-message-type] (decode-uint16-and-split after-size)]
    [{:size size
      :message-type message-type}
     after-message-type]))

(defn encode-message
  [msg]
  (concat
    (encode-header (+ (count (:bytes msg)) header-size) (:message-type msg))
    (:bytes msg)))