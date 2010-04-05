(ns org.gnu.clojure.gnunet.identity)

(defn bit-count-to-bytes [x] (quot (+ 7 x) 8))

(defn bigint-to-bytes [x]
  (let [len (bit-count-to-bytes (.bitLength x))
        a (.toByteArray x)]
    (drop (- (alength a) len) a)))

(defn short-to-bytes [x]
  (list (quot x 256) (rem x 256)))

(defn rsa-public-key-binary-encoded [key]
  (let [modulus (bigint-to-bytes (.getModulus key)) 
        exponent (bigint-to-bytes (.getPublicExponent key))
        len (+ (count modulus) (count exponent) 4)]
    (concat
      (short-to-bytes len)
      (short-to-bytes (count modulus))
      modulus
      exponent
      (short-to-bytes 0))))