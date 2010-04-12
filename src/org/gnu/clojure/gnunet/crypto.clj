(ns org.gnu.clojure.gnunet.crypto
  (:import (java.security KeyPairGenerator MessageDigest)
    java.security.spec.RSAKeyGenParameterSpec))

(defn generate-rsa-keypair
  "Generate a 2048 bit RSA keypair."
  []
  (let [rsa (KeyPairGenerator/getInstance "RSA")
        spec (RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec)
    (.generateKeyPair rsa)))

(defn sha-512
  "Compute the SHA-512 digest of a sequence of bytes."
  [x]
  (let [sha (MessageDigest/getInstance "SHA-512")]
    (.digest sha (byte-array x))))
