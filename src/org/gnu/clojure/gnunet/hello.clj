(ns org.gnu.clojure.gnunet.hello
  (:use (org.gnu.clojure.gnunet parser message peer crypto)
    clojure.contrib.monads))

(def message-type-hello 16)

(defn encode-transport
  [transport]
  (concat
    (encode-utf8 (:name transport))
    (encode-int16 (count (:encoded-address transport)))
    (encode-date (:expiration transport))
    (:encoded-address transport)))

(def parse-transport
  (domonad parser-m [name- parse-utf8
                     address-length parse-uint16
                     expiration parse-date
                     encoded-address (items address-length)]
    {:name name-
     :expiration expiration
     :encoded-address encoded-address}))

(defn encode-hello
  "Encode a hello message."
  [hello]
  (concat
    (encode-int32 0)
    (encode-rsa-public-key (:public-key hello))
    (mapcat encode-transport (:transports hello))))

(def parse-hello
  (domonad parser-m [padding parse-uint32
                     :when (== padding 0)
                     public-key parse-rsa-public-key
                     transports (none-or-more parse-transport)]
    {:public-key public-key
     :transports transports}))
