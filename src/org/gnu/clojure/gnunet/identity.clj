(ns org.gnu.clojure.gnunet.identity)

(defn bit-count-to-bytes [x] (quot (+ 7 x) 8))

(defn encode-bigint
  "Convert a bigInteger to a sequence of bytes in bigendian."
  [x]
  (let [len (bit-count-to-bytes (.bitLength x))
        a (.toByteArray x)]
    (drop (- (alength a) len) a)))

(defn encode-short
  "Convert a short to a sequence of bytes in bigendian."
  [x]
  (list (byte (quot x 256)) (byte (rem x 256))))

(defn encode-rsa-public-key
  "Convert an RSA public key to a sequence of bytes in gnunet format"
  [key]
  (let [modulus (encode-bigint (.getModulus key)) 
        modulus-len (count modulus)
        exponent (encode-bigint (.getPublicExponent key))
        exponent-len (count exponent)]
    (concat
      (encode-short (+ modulus-len exponent-len 4))
      (encode-short modulus-len)
      modulus
      exponent
      (encode-short 0))))

(defn generate-rsa-keypair
  "Generate a 2048 bit RSA keypair"
  []
  (let [rsa (java.security.KeyPairGenerator/getInstance "RSA")
        spec (java.security.spec.RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec)
    (.generateKeyPair rsa)))

(defn sha-512
  [x]
  (let [sha (java.security.MessageDigest/getInstance "SHA-512")]
    (.digest sha (byte-array x))))