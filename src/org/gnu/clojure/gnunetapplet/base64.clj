(ns org.gnu.clojure.gnunetapplet.base64
  (:import (sun.misc BASE64Encoder BASE64Decoder)))

(defn base64-encode
  [byte-seq]
  (let [b64 (BASE64Encoder.)]
    (.encode b64 (byte-array byte-seq))))

(defn base64-decode
  [string]
  (let [b64 (BASE64Decoder.)]
    (.decodeBuffer b64 string)))
