(ns org.gnu.clojure.gnunet.exception
  (:use clojure.contrib.monads))

(def exception-m (maybe-t state-m :exception))

(with-monad exception-m

(def nop (m-result nil))

(def break m-zero)
)

(defmacro send-do-exception-m!
  [target-agent steps expr]
  `(send ~target-agent
    (fn [state#]
      (second ((domonad exception-m ~steps ~expr) state#)))))
