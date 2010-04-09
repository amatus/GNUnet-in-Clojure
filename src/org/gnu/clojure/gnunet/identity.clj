(ns org.gnu.clojure.gnunet.identity
  (:use (org.gnu.clojure.gnunet crypto message)))

(defn bit-count-to-bytes [x] (quot (+ 7 x) 8))

(defn encode-bigint
  "Convert a bigInteger to a sequence of bytes in network order."
  [x]
  (let [len (bit-count-to-bytes (.bitLength x))
        a (.toByteArray x)]
    (drop (- (alength a) len) a)))

(defn encode-rsa-public-key
  "Convert an RSA public key to a sequence of bytes in gnunet format."
  [key]
  (let [modulus (encode-bigint (.getModulus key)) 
        modulus-len (count modulus)
        exponent (encode-bigint (.getPublicExponent key))
        exponent-len (count exponent)]
    (concat
      (encode-int16 (+ modulus-len exponent-len 4))
      (encode-int16 modulus-len)
      modulus
      exponent
      (encode-int16 0))))

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [keypair]
  (sha-512 (encode-rsa-public-key (.getPublic keypair))))
