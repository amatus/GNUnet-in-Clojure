(ns org.gnu.clojure.gnunet.udp
  (:use org.gnu.clojure.gnunet.inet))

(defn pick-address
  [addresses]
  (let [parsed-addresses (map #(first (parse-address (key %))) addresses)
        usable-addresses (filter #(and % (is-unicast-address (.getAddress %)))
                           parsed-addresses)]
  (first usable-addresses)))

(defn udp-send!
  [remote-peer addresses encoded-message]
  (let [address (pick-address addresses)]
    ))
