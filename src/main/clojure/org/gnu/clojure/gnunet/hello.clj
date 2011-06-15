(ns org.gnu.clojure.gnunet.hello
  (:use (org.gnu.clojure.gnunet parser message peer crypto)
    clojure.contrib.monads))

(def message-type-hello 16)

(defn encode-transport-address
  [address]
  (concat
    (encode-utf8 (:transport address))
    (encode-int16 (count (:encoded-address address)))
    (encode-date (:expiration address))
    (:encoded-address address)))

(def parse-transport-address
  (domonad parser-m [transport parse-utf8
                     address-length parse-uint16
                     expiration parse-date
                     encoded-address (items address-length)]
    {:transport transport
     :expiration expiration
     :encoded-address encoded-address}))

(defn encode-hello
  "Encode a hello message."
  [hello]
  (concat
    (encode-int32 0)
    (encode-rsa-public-key (:public-key hello))
    (mapcat encode-transport-address (:transport-addresses hello))))

(def parse-hello
  (domonad parser-m [padding parse-uint32
                     :when (== padding 0)
                     public-key parse-rsa-public-key
                     addresses (none-or-more parse-transport-address)]
    {:public-key public-key
     :transport-addresses addresses}))
