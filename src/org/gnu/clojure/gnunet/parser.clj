(ns org.gnu.clojure.gnunet.parser
  (:use clojure.contrib.monads))

(def parser-m (state-t maybe-m))

(defn item
  "Parser which returns the first item of input."
  [xs]
  (when (not (empty? xs)) [(first xs) (rest xs)]))

(defn items
  "Produces a parser that returns the first n items of input."
  [n]
  (with-monad parser-m
    (m-when (> n 0)
      (domonad [x item
                xs (items (- n 1))]
        (cons x xs)))))