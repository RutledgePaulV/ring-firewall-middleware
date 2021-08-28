(defproject org.clojars.rutledgepaulv/ring-firewall-middleware "0.1.6-SNAPSHOT"

  :description
  "A library for filtering ring requests by client ip address."

  :url
  "https://github.com/rutledgepaulv/ring-firewall-middleware"

  :license
  {:name "MIT License" :url "http://opensource.org/licenses/MIT" :year 2020 :key "mit"}

  :scm
  {:name "git" :url "https://github.com/rutledgepaulv/ring-firewall-middleware"}

  :pom-addition
  [:developers
   [:developer
    [:name "Paul Rutledge"]
    [:url "https://github.com/rutledgepaulv"]
    [:email "rutledgepaulv@gmail.com"]
    [:timezone "-5"]]]

  :deploy-repositories
  [["releases" :clojars] ["snapshots" :clojars]]

  :dependencies
  [[org.clojure/clojure "1.10.3"]]

  :repl-options
  {:init-ns ring-firewall-middleware.core})
