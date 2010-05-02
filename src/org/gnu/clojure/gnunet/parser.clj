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

(defn is
  "Produces a parser that matches an item which satisfies the given predicate."
  [p]
  (domonad parser-m [x item
                     :when (p x)]
    x))

(defn optional
  "Makes a parser optional."
  [mv]
  (with-monad parser-m
    (m-plus mv (m-result nil))))

(def one-or-more)

(defn none-or-more
  "Makes a parser repeat none or more times."
  [mv]
  (optional (one-or-more mv)))

(defn one-or-more
  "Makes a parser repeat one or more times."
  [mv]
  (domonad parser-m [x mv
                     xs (none-or-more mv)]
    (cons x xs)))
