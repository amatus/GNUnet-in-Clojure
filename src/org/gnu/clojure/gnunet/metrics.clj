(ns org.gnu.clojure.gnunet.metrics)

(defn metric-set
  [peer metric value]
  (send (:metrics-agent peer)
    (fn [metrics]
      (assoc metrics metric value))))

(defn metric-add
  ([peer metric value]
    (metric-add peer metric value 0))
  ([peer metric value zero]
    (send (:metrics-agent peer)
      (fn [metrics]
        (let [old-value (get metrics metric zero)]
          (assoc metrics metric (+ old-value value)))))))
