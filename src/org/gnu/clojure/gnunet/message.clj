(ns org.gnu.clojure.gnunet.message
  (:use org.gnu.clojure.gnunet.parser
    clojure.contrib.monads)
  (:import java.math.BigInteger java.lang.String java.util.Date))

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

(def parse-uint16
  (domonad parser-m [xs (items 2)] (int (decode-uint xs))))

(def parse-uint32
  (domonad parser-m [xs (items 4)] (long (decode-uint xs))))

(def parse-uint64
  (domonad parser-m [xs (items 8)] (decode-uint xs)))

(defn parse-uint
  [n]
  (domonad parser-m [xs (items n)] (decode-uint xs)))

(defn encode-utf8
  "Converts a string into a null-terminated sequence of bytes in UTF-8."
  [string]
  (concat
    (.getBytes string "UTF-8")
    (list (byte 0))))

(def parse-utf8
  (domonad parser-m [xs (none-or-more (is #(not (== 0 %))))
                     zero item
                     :when (== zero 0)]
    (String. (byte-array xs) "UTF-8")))

(defn encode-date
  [date]
  (encode-int64 (.getTime date)))

(def parse-date
  (domonad parser-m [x parse-uint64] (Date. (long x))))

(defn encode-header
  "Encode a gnunet message header."
  [hdr]
  (concat
    (encode-int16 (:size hdr))
    (encode-int16 (:message-type hdr))))

(def header-size (count (encode-header {:size 0 :message-type 0})))

(def parse-header
  (domonad parser-m [size parse-uint16
                     message-type parse-uint16]
    {:size size
     :message-type message-type}))

(defn encode-message
  [msg]
  (concat
    (encode-header (+ (count (:bytes msg)) header-size) (:message-type msg))
    (:bytes msg)))

(def parse-message
  (domonad parser-m [{message-type :message-type size :size} parse-header
                     message (items (- size header-size))]
    {:message-type message-type
     :bytes message}))

(defn parse-message-types
  "Produces a parser for messages of the given types.
   The parser does not fail if the message-type specific parser does not consume
   the entire message."
  [parser-map]
  (fn [s]
    (when-let [xs (parse-message s)]
      (let [[{message-type :message-type message :bytes} ss] xs]
        (when (contains? parser-map message-type)
          (when-let [xs ((get parser-map message-type) message)]
            [{:message-type message-type :message (first xs)} ss]))))))
