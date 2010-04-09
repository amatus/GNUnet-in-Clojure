(ns org.gnu.clojure.gnunet.hello
  (:use (org.gnu.clojure.gnunet message identity)))

(def message-type-hello 16)

(defn encode-transport
  [transport]
  (concat
    (.getBytes (:name transport) "UTF-8")
    (list (byte 0))
    (encode-int32 (count (:encoded-address transport)))
    (encode-int64 (.getTime (:expiration transport)))
    (:encoded-address transport)))

(defn encode-hello
  "Encode a hello message."
  [public-key transports]
  (let [padding (encode-int32 0)
        encoded-key (encode-rsa-public-key public-key)
        encoded-transports (mapcat encode-transport transports)
        size (+ header-size
               (count padding)
               (count encoded-key)
               (count encoded-transports))]
    (concat
      (encode-header size message-type-hello)
      padding
      encoded-key
      encoded-transports)))
