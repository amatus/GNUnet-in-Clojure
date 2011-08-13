#!/bin/sh
exec java -cp www/clojure.jar:www/monads.jar:www/generic.jar:www/json.jar:www/types.jar:src/main/clojure clojure.main
