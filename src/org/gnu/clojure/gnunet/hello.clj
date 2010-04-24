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

(defn decode-transports-and-split
  [a]
  )

(defn encode-hello
  "Encode a hello message."
  [hello]
  (let [padding (encode-int32 0)
        encoded-key (encode-rsa-public-key (:public-key hello))
        encoded-transports (mapcat encode-transport (:transports hello))
        size (+ header-size
               (count padding)
               (count encoded-key)
               (count encoded-transports))]
    (concat
      (encode-header size message-type-hello)
      padding
      encoded-key
      encoded-transports)))

(defn decode-hello-and-split
  [a]
  (let [[header after-header] (decode-header-and-split a)
        [padding after-padding] (split-at 4 after-header)
        [public-key after-public-key] (decode-rsa-public-key-and-split
                                        after-padding)
        [transports after-transports] (decode-transports-and-split
                                        after-public-key)]
    [{:public-key public-key
      :transports transports}
     after-transports]))
