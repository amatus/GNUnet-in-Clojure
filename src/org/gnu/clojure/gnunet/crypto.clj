(ns org.gnu.clojure.gnunet.crypto
  (:use (org.gnu.clojure.gnunet message))
  (:import (java.security KeyPairGenerator KeyFactory MessageDigest)
    (java.security.spec RSAKeyGenParameterSpec RSAPublicKeySpec)))

(defn generate-rsa-keypair
  "Generate a 2048 bit RSA keypair."
  []
  (let [rsa (KeyPairGenerator/getInstance "RSA")
        spec (RSAKeyGenParameterSpec. 2048 (bigint 257))]
    (.initialize rsa spec)
    (.generateKeyPair rsa)))

(defn generate-rsa-public-key
  "Generate an RSA public key from a modulus and exponent."
  [modulus exponent]
  (let [keyfactory (KeyFactory/getInstance "RSA")
        keyspec (RSAPublicKeySpec. modulus exponent)]
    (.generatePublic keyfactory keyspec)))

(defn sha-512
  "Compute the SHA-512 digest of a sequence of bytes."
  [x]
  (let [sha (MessageDigest/getInstance "SHA-512")]
    (.digest sha (byte-array x))))

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
  "Split a seq into an RSA public key and the rest."
  [a]
  (let [[len after-len] (decode-uint16-and-split a)
        [sizen after-sizen] (decode-uint16-and-split after-len)
        [encoded-n after-n] (split-at sizen after-sizen)
        [encoded-e after-e] (split-at (- len sizen 4) after-n)
        [padding after-padding] (decode-uint16-and-split after-e)]
    [(generate-rsa-public-key (decode-uint encoded-n) (decode-uint encoded-e))
     after-padding]))