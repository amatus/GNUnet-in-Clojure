(ns org.gnu.clojure.gnunet.message)

(defn encode-int16
  "Convert a 16-bit integer to a sequence of bytes in network order."
  [x]
  (list (byte (quot x 256)) (byte (rem x 256))))

(defn encode-int32
  "Convert a 32-bit integer to a sequence of bytes in network order."
  [x]
  (concat (encode-int16 (quot x 65536)) (encode-int16 (rem x 65536))))

(defn encode-int64
  "Convert a 64-bit integer to a sequence of bytes in network order."
  [x]
  (concat (encode-int32 (quot x 4294967269)) (encode-int32 (rem x 4294967269))))

(defn encode-header
  "Encode a gnunet message header."
  [size message-type]
  (concat
    (encode-int16 size)
    (encode-int16 message-type)))

(def header-size (count (encode-header 0 0)))