(ns org.gnu.clojure.gnunet.transport
  (:use (org.gnu.clojure.gnunet core crypto exception hello message metrics
          parser peer util)
    clojure.contrib.monads)
  (:import (java.util Date Calendar)))

(defn hello-address-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/HOUR_OF_DAY 12))))

(defn pong-expiration
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/HOUR_OF_DAY 1))))

(defn idle-connection-timeout
  []
  (.getTime (doto (Calendar/getInstance) (.add Calendar/MINUTE 5))))

(def message-type-ping 32)
(def message-type-pong 33)

(def signature-purpose-pong-own 1)
(def signature-purpose-pong-using 2)

(defn encode-ping
  [ping]
  (concat
    (encode-int32 (:challenge ping))
    (:peer-id ping)
    (if-let [transport (:transport ping)]
      (concat
        (encode-utf8 (:transport ping))
        (:encoded-address ping)))))

(def parse-ping
  (domonad parser-m
    [challenge parse-uint32
     peer-id (items id-size)
     transport (optional parse-utf8)
     encoded-address (none-or-more item)]
    {:challenge challenge
     :peer-id peer-id
     :transport transport
     :encoded-address encoded-address}))

(defn encode-pong-signed-material
  [pong]
  (let [transport (when (:transport pong) (encode-utf8 (:transport pong)))
        address-length (+ (count transport) (count (:encoded-address pong)))]
    (encode-signed (:signature-purpose pong)
      (concat
        (encode-date (:expiration pong))
        (:peer-id pong)
        (encode-int32 address-length)
        transport
        (:encoded-address pong)))))

(defn encode-pong
  [pong signed-material]
  (concat
    (encode-int32 (:challenge pong))
    (:signature pong)
    signed-material))

(def parse-pong
  (domonad parser-m
    [challenge parse-int32
     signature (items signature-size)
     signed (parse-signed
              (domonad parser-m
                [expiration parse-date
                 peer-id (items id-size)
                 address-length parse-uint32
                 transport (none-or-more (satisfy #(not (== 0 %))))
                 zero item
                 :let [transport-length (inc (count transport))]
                 :when (>= address-length transport-length)
                 encoded-address (items (- address-length transport-length))]
                {:expiration expiration
                 :peer-id peer-id
                 :transport (String. (byte-array transport) "UTF-8")
                 :encoded-address encoded-address}))
     :let [signature-purpose (:purpose signed)]
     :when (or (== signature-purpose signature-purpose-pong-own)
             (== signature-purpose signature-purpose-pong-using))
     residue (optional item)
     :when (nil? residue)]
    (conj {:challenge challenge
           :signature signature
           :signature-purpose signature-purpose
           :signed-material (:signed-material signed)}
      (:parsed signed))))

(defn list-transport-addresses
  "Generate a list of transport descriptions."
  [addresses-map]
  (for [transport addresses-map
        address (val transport)]
    (conj
      {:transport (key transport) :encoded-address (key address)}
      (val address))))

(defn merge-address-info
  "Merge two address-info maps."
  [a b]
  (conj a b {:expiration (my-max (:expiration a) (:expiration b))}))

(defn merge-transport-addresses
  "Merge a list of transport descriptions into a transports-agent map. The input
   list is generated from parse-hello or list-transports. The input map is
   described in peer.clj."
  [address-map address-list]
  (reduce (fn [address-map new-address]
            (if-let [transport (address-map (:transport new-address))]
              (if-let [address-info (transport (:encoded-address new-address))]
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (merge-address-info address-info
                      (dissoc new-address :transport :encoded-address))))
                (assoc address-map (:transport new-address)
                  (assoc transport (:encoded-address new-address)
                    (dissoc new-address :transport :encoded-address))))
              (assoc address-map (:transport new-address)
                {(:encoded-address new-address)
                 (dissoc new-address :transport :encoded-address)})))
    address-map
    address-list))

(defn expire-transport-addresses
  [min-expiration addresses-list]
  (filter #(not (.after min-expiration (:expiration %))) addresses-list))

(defn hello-for-peer-message
  [peer]
  {:message-type message-type-hello
   :bytes (encode-hello
            {:public-key (deref (:public-key-atom peer))
             :transport-addresses (list-transport-addresses
                                    (deref
                                      (:transport-addresses-agent peer)))})})

(defn ping-message
  [remote-peer address challenge]
  {:message-type message-type-ping
   :bytes (encode-ping {:challenge challenge
                        :peer-id (:id remote-peer)
                        :transport (:transport address)
                        :encoded-address (:encoded-address address)})})

(defn update-transport-addresses
  [addresses new-addresses]
  (merge-transport-addresses {}
    (expire-transport-addresses (Date.)
      (concat (list-transport-addresses addresses) new-addresses))))

(defn update-remote-peers!
  [remote-peers peer-id hello]
  (let [remote-peer (remote-peers peer-id)]
    (if remote-peer
      (do
        (if (:public-key hello)
          (swap! (:public-key-atom remote-peer)
            #(if (nil? %) (:public-key hello))))
        (send (:transport-addresses-agent remote-peer)
          update-transport-addresses
          (:transport-addresses hello))
        remote-peers)
      (assoc remote-peers peer-id
        (struct-map remote-peer-struct
          :public-key-atom (atom (:public-key hello))
          :id peer-id
          :transport-addresses-agent (agent
                                       (merge-transport-addresses {}
                                         (:transport-addresses hello)))
          :state-agent (agent {:is-connected false}))))))

(defn verify-transport-address!
  [peer remote-peer address]
  (second
    ((domonad exception-m
       [address (fetch-state)
        :when (not (or (contains? address :latency)
                     (contains? address :send-time)))
        :when-let [transport ((deref (:transports-agent peer))
                               (:transport address))]
        :let [challenge (.nextInt (:random peer))]
        _ (set-state
            (conj address
              {:send-time (Date.)    ;; TODO: Now is not the actual send time.
               :challenge challenge}))]
       ((:emit-messages! transport) transport remote-peer
         (:encoded-address address) nil
         [(hello-for-peer-message peer)
          (ping-message remote-peer address challenge)])) address)))

(defn verify-transport-addresses!
  [addresses peer remote-peer]
  (merge-transport-addresses {}
    (map (partial verify-transport-address! peer remote-peer)
      (list-transport-addresses addresses))))

(defn verify-remote-peers!
  [remote-peers peer]
  (doseq [[_ remote-peer] remote-peers]
    (send (:transport-addresses-agent remote-peer)
      verify-transport-addresses! peer remote-peer))
  remote-peers)

(defn admit-hello!
  "Updates peer:remote-peers-agent with new information contained in hello."
  [peer hello]
  (let [peer-id (generate-id (:public-key hello))]
    (if (not (= peer-id (:id peer)))
      (let [remote-peers-agent (:remote-peers-agent peer)]
        (send remote-peers-agent update-remote-peers! peer-id hello)
        (send remote-peers-agent verify-remote-peers! peer)))))

(defn handle-hello!
  [peer message]
  (when-let [hello (first (parse-hello (:bytes message)))]
    (admit-hello! peer hello)))

(defn send-pong-own!
  [peer remote-peer ping]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [transport-addresses ((deref (:transport-addresses-agent peer))
                               (:transport ping))
         ;; XXX: Here we're looking for an exact match, gnunet allows transport
         ;; plugins to do inexact matches.
         :when (contains? transport-addresses (:encoded-address ping))
         pong {:challenge (:challenge ping)
               :signature-purpose signature-purpose-pong-own
               :expiration (pong-expiration)
               :peer-id (:id peer)
               :transport (:transport ping)
               :encoded-address (:encoded-address ping)}
         signed-material (encode-pong-signed-material pong)
         signature (rsa-sign (:private-key peer) signed-material)
         pong (assoc pong :signature signature)
         encoded-pong (encode-pong pong signed-material)
         state (deref (:state-agent remote-peer))]
        (if (:is-connected state)
          (let [transport (:connected-transport state)
                encoded-address (:connected-address state)]
            ((:emit-messages! transport) transport remote-peer encoded-address
              nil [{:message-type message-type-pong :bytes encoded-pong}]))
          (doseq [transports (deref (:transport-addresses-agent remote-peer))
                  address (val transports)]
            (when-let [transport ((deref (:transports-agent peer))
                                   (key transports))]
              ((:emit-messages! transport) transport remote-peer (key address)
                nil
                [{:message-type message-type-pong :bytes encoded-pong}]))))))))

(defn send-pong-using!
  [peer remote-peer address ping]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (let
        [state (deref (:state-agent remote-peer))
         pong {:challenge (:challenge ping)
               :signature-purpose signature-purpose-pong-using
               :expiration (pong-expiration)
               :peer-id (:id remote-peer)
               :transport (:transport address)
               :encoded-address (:encoded-address address)}
         signed-material (encode-pong-signed-material pong)
         signature (rsa-sign (:private-key peer) signed-material)
         pong (assoc pong :signature signature)
         encoded-pong (encode-pong pong signed-material)
         state (deref (:state-agent remote-peer))]
        (if (:is-connected state)
          (let [transport (:connected-transport state)
                encoded-address (:connected-address state)]
            ((:emit-messages! transport) transport remote-peer encoded-address
              nil [{:message-type message-type-pong :bytes encoded-pong}]))
          (doseq [transports (deref (:transport-addresses-agent remote-peer))
                  address (val transports)]
            (when-let [transport ((deref (:transports-agent peer))
                                   (key transports))]
              ((:emit-messages! transport) transport remote-peer (key address)
                nil
                [{:message-type message-type-pong :bytes encoded-pong}]))))))))

(defn handle-ping!
  [peer remote-peer address message]
  (when-let [ping (first (parse-ping (:bytes message)))]
    (cond
      (not (= (:peer-id ping) (:id peer))) nil
      (:transport ping) (send-pong-own! peer remote-peer ping)
      :else (send-pong-using! peer remote-peer address ping))))

(defn handle-pong-own!
  [peer remote-peer pong]
  (.execute (:cpu-bound-executor peer)
    (fn []
      (domonad maybe-m
        [public-key (deref (:public-key-atom remote-peer))
         :when (rsa-verify public-key (:signed-material pong)
                 (:signature pong))]
        (send-do-exception-m! (:transport-addresses-agent remote-peer)
          [address (with-state-field (:transport pong)
                     (fetch-val (:encoded-address pong)))
           :when (= (:challenge address) (:challenge pong))
           _ (with-state-field (:transport pong)
               (set-val (:encoded-address pong)
                 {:expiration (hello-address-expiration)
                  :latency (- (.getTime (Date.))
                             (.getTime (:send-time address)))}))]
          (metric-add! peer "Peer addresses considered valid" 1))))))

(defn handle-pong-using!
  [peer remote-peer pong]
  ;; TODO - fill in this case
  (.write *out* "We don't handle PONG_USING yet!\n"))
  
(defn handle-pong!
  [peer message]
  (domonad maybe-m
    [pong (first (parse-pong (:bytes message)))
     :when-not (.after (Date.) (:expiration pong))
     remote-peer ((deref (:remote-peers-agent peer)) (:peer-id pong))]
    (condp == (:signature-purpose pong)
      signature-purpose-pong-own (handle-pong-own! peer remote-peer pong)
      signature-purpose-pong-using (handle-pong-using! peer remote-peer pong)
      nil)))

(defn emit-callback!
  [peer transport remote-peer encoded-address result]
  (when result
    (let [addresses ((deref (:transport-addresses-agent remote-peer))
                      (:name transport))
          address (addresses encoded-address)]
      (if (contains? address :latency)
        (send (:state-agent remote-peer)
          (fn [state]
            (conj state {:is-connected true
                         :connected-transport transport
                         :connected-address encoded-address})))))))

(defn admit-message!
  [peer sender-id address message]
  ;; (.write *out* (str "Received " message "\n"))
  (send (:remote-peers-agent peer)
    (fn [remote-peers]
      (let [remote-peers (update-remote-peers! remote-peers
                           sender-id {:transport-addresses [address]})
            remote-peer (remote-peers sender-id)]
        (condp = (:message-type message)
          message-type-hello (handle-hello! peer message)
          message-type-ping (handle-ping! peer remote-peer address message)
          message-type-pong (handle-pong! peer message)
          (handle-receive! peer remote-peer message))
        remote-peers))))
