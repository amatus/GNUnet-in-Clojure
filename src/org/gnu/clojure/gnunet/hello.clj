(ns org.gnu.clojure.gnunet.hello
  (:use (org.gnu.clojure.gnunet parser message identity crypto)
    clojure.contrib.monads)
  (:import java.util.Date))

(def message-type-hello 16)

(defn encode-transport
  [transport]
  (concat
    (encode-utf8 (:name transport))
    (encode-int16 (count (:bytes transport)))
    (encode-date (:expiration transport))
    (:bytes transport)))

(def parse-transport
  (domonad parser-m [name- parse-utf8
                     address-length parse-uint16
                     expiration parse-date
                     encoded-address (items address-length)]
    {:name name-
     :expiration expiration
     :bytes encoded-address}))

(defn list-transports
  "Generate a list of transport descriptions."
  [transport-map]
  (for [transport transport-map
        address (val transport)]
    {:name (key transport)
     :bytes (key address)
     :expiration (val address)}))

(defn encode-hello
  "Encode a hello message."
  [hello]
  (concat
    (encode-int32 0)
    (encode-rsa-public-key (:public-key hello))
    (mapcat encode-transport (list-transports (:transports hello)))))

(defn my-max
  "Return the maximum in a collection of comparable values."
  [& coll]
  (last (sort coll)))

(defn merge-transports
  "Merge a list of transport descriptions into a map of maps of
   expiration times, keyed first by transport name and then by
   transport address, and then filter by min-expiration"
  [min-expiration transport-map transport-list]
  (reduce (fn [transport-map transport]
            (let [addresses (transport-map
                              (:name transport)
                              {(:bytes transport) (:expiration transport)})
                  expiration (addresses
                               (:bytes transport)
                               (:expiration transport))]
              (if (and
                    (< 0 (compare min-expiration expiration))
                    (< 0 (compare min-expiration (:expiration transport))))
                (let [less-addresses (dissoc addresses (:bytes transport))]
                  (if (empty? less-addresses)
                    (dissoc transport-map (:name transport))
                    (assoc transport-map (:name transport) less-addresses)))
                (assoc transport-map
                  (:name transport)
                  (assoc addresses
                    (:bytes transport)
                    (my-max (:expiration transport) expiration))))))
    transport-map
    transport-list))

(def parse-hello
  (domonad parser-m [padding parse-uint32
                     :when (== padding 0)
                     public-key parse-rsa-public-key
                     transports (none-or-more parse-transport)]
    {:public-key public-key
     :transports (merge-transports (Date. (long 0)) {} transports)}))
