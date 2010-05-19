(ns org.gnu.clojure.gnunet.identity
  (:use (org.gnu.clojure.gnunet crypto message)))

(defn generate-id
  "Generate the SHA-512 digest of the encoded public key."
  [keypair]
  (sha-512 (encode-rsa-public-key (.getPublic keypair))))

(def id-size (count (sha-512 ())))
