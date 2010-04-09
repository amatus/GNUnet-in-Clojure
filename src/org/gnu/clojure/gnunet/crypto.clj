(ns org.gnu.clojure.gnunet.crypto)

(defn generate-rsa-keypair
  "Generate a 2048 bit RSA keypair."
  []
  (let [rsa (java.security.KeyPairGenerator/getInstance "RSA")
        spec (java.security.spec.RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec)
    (.generateKeyPair rsa)))

(defn sha-512
  "Compute the SHA-512 digest of a sequence of bytes."
  [x]
  (let [sha (java.security.MessageDigest/getInstance "SHA-512")]
    (.digest sha (byte-array x))))