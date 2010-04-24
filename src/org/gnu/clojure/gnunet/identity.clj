(ns org.gnu.clojure.gnunet.identity
  (:use (org.gnu.clojure.gnunet crypto message)))

(defn encode-rsa-public-key
  "Convert an RSA public key to a sequence of bytes in gnunet format."
  [public-key]
  (let [modulus (encode-int (.getModulus public-key)) 
        modulus-len (count modulus)
        exponent (encode-int (.getPublicExponent public-key))
        exponent-len (count exponent)]
    (concat
      (encode-int16 (+ modulus-len exponent-len 4))
      (encode-int16 modulus-len)
      modulus
      exponent
      (encode-int16 0))))

(defn decode-rsa-public-key-and-split
  [a]
  )

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [keypair]
  (sha-512 (encode-rsa-public-key (.getPublic keypair))))
