[![Build Status](https://travis-ci.com/rutledgepaulv/ring-firewall-middleware.svg?branch=master)](https://travis-ci.com/rutledgepaulv/ring-firewall-middleware)
[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.rutledgepaulv/ring-firewall-middleware.svg)](https://clojars.org/org.clojars.rutledgepaulv/ring-firewall-middleware)

<img src="./docs/ring-of-fire.jpg" title="brisingr" width="300" height="300" align="left" padding="5px"/>
<small>
<br/><br/><br/><br/>
A collection of efficient ring middleware for limiting access to your application code 
based on things like source ip, concurrency, and rate of requests. Uses no dependencies.
</small>
<br clear="all" /><br />

---

## Allow IPs

If you don't already understand the security implications of ip firewalling please read
[understanding source ip based security](#understanding-source-ip-based-security). Your allow-list must encompass the
intended client IPs as well as any intermediate reverse proxies that add themselves to the forwarded headers. This
middleware supports both IPv4 and IPv6 ranges.

```clojure

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn admin-handler [request]
  {:status 200 :body "Top Secret!"})

(def internal-network-only
  (rfm/wrap-allow-ips admin-handler {:allow-list #{"10.0.0.0/8"}}))

(jetty/run-jetty internal-network-only {:port 3000})

```

## Deny IPs

If you don't already understand the security implications of ip firewalling please read
[understanding source ip based security](#understanding-source-ip-based-security). If any of the IPs in your deny-list
appear in the forwarded headers or as the source IP of the network packets then the request will be denied. This
middleware supports both IPv4 and IPv6 ranges.

In most cases you should be using `wrap-allow-ips` and not `wrap-deny-ips`. This middleware is only useful for
implementing naive banning of poorly behaved clients and should not be relied upon as a robust way to restrict access to
your site.

```clojure

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn site-handler [request]
  {:status 200 :body "Runescape"})

(def kiddies
  (->> (slurp "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt")
       (clojure.string/split-lines)
       (keep #(re-find #"(\d+\.\d+\.\d+\.\d+)" %))
       (map second)
       (into #{})))

(def keep-out-the-script-kiddies
  (rfm/wrap-deny-ips site-handler {:deny-list kiddies}))

(jetty/run-jetty keep-out-the-script-kiddies {:port 3000})

```

## Concurrency Throttle

You can use concurrency throttling to limit the number of requests that simultaneously exercise some section of your
app. This is useful if you have any endpoints that are particularly expensive and may cause instability if invoked
enough.

It's a "throttle" and not a "limit" because new requests that would exceed the max-concurrency will block until an
earlier request completes and then are processed (unless it takes so long that the client decides to stop waiting).

```clojure 

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn expensive [request]
  {:status 200 :body "crawl the entire database"})
  
(def controlled-chaos
  (rfm/wrap-concurrency-throttle expensive {:max-concurrent 1}))
  
(jetty/run-jetty controlled-chaos {:port 3000})

```

## Concurrency Limit

You can use concurrency limiting to limit the number of requests that simultaneously exercise some section of your app.
This is useful if you have any endpoints that are particularly expensive and may cause instability if invoked enough.

It's a "limit" and not a "throttle" because new requests that would exceed the max-concurrency receive an error response
from the server and will need to be retried by the client at a later time.

```clojure 

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn expensive [request]
  {:status 200 :body "crawl the entire database"})
  
(def controlled-chaos
  (rfm/wrap-concurrency-limit expensive {:max-concurrent 1}))
  
(jetty/run-jetty controlled-chaos {:port 3000})

```

## Rate Throttle

You can use rate throttling to control the number of requests that exercise portions of your app over a period of time.
This is useful if you have endpoints that are particularly expensive and may cause instability or unfairness to other
users if invoked frequently enough.

It's a "throttle" and not a "limit" because new requests that would exceed the max-requests in a period will block until
the request can be made without exceeding the limit and then be processed (unless it takes so long that the client
decided to stop waiting).

```clojure 

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn expensive [request]
  {:status 200 :body "crawl the entire database"})
  
(def controlled-chaos
  (rfm/wrap-rate-throttle expensive {:max-requests 100 :period 60000}))
  
(jetty/run-jetty controlled-chaos {:port 3000})

```

## Rate Limit

You can use rate limiting to control the number of requests that exercise portions of your app over a period of time.
This is useful if you have endpoints that are particularly expensive and may cause instability or unfairness to other
users if invoked frequently enough.

It's a "limit" and not a "throttle" because new requests that would exceed the max-requests in a period will receive an
error response from the server and will need to be retried by the client at a later time.

```clojure 

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn expensive [request]
  {:status 200 :body "crawl the entire database"})
  
(def controlled-chaos
  (rfm/wrap-rate-limit expensive {:max-requests 100 :period 60000}))
  
(jetty/run-jetty controlled-chaos {:port 3000})

```

## Maintenance Throttle

This middleware adds request coordination so that you can enter and exit a "maintenance mode" from elsewhere in your
code. When maintenance mode is active new requests are blocked and in-flight requests are awaited before executing the
maintenance code.

```clojure

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn site-handler [request]
  {:status 200 :body "My site is up!"})

(def maintainable
  (rfm/wrap-maintenance-throttle site-handler))

(jetty/run-jetty maintainable {:port 3000 :join? false})


(defn do-maintenance! []
  ; this macro will wait to execute migrate-the-database!
  ; until all in-flight requests are complete and no new
  ; requests will be permitted until it completes.
  (rfm/with-maintenance-mode :world 
     (migrate-the-database!)))

```

## Maintenance Limit

This middleware adds request coordination so that you can enter and exit a "maintenance mode" from elsewhere in your
code. When maintenance mode is active new requests are denied and in-flight requests are awaited before executing the
maintenance code.

```clojure

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn site-handler [request]
  {:status 200 :body "My site is up!"})

(def maintainable
  (rfm/wrap-maintenance-limit site-handler))

(jetty/run-jetty maintainable {:port 3000 :join? false})


(defn do-maintenance! []
  ; this macro will wait to execute migrate-the-database!
  ; until all in-flight requests are complete and no new
  ; requests will be permitted until it completes.
  (rfm/with-maintenance-mode :world 
     (migrate-the-database!)))

```

---

## Understanding Source IP Based Security

There is a lot of misinformation on the web about the security of IP firewalling. I will attempt to provide some clarity
for the typical web developer.

#### On Packet Source IP Spoofing

- The source ip in a network packet can be set to whatever an attacker wants
- Packets returned from a server are sent to whatever source ip was provided
- It would be pointless for an attacker to send packets pretending to come from somewhere they already have access to
  receive responses
- An attacker will be able to send a bad source ip and get a packet through to you, but they won't ever receive any
  response packets
- HTTP is built on the TCP protocol and requires at least one round trip of network packets to establish a connection
- An attacker cannot use source ip spoofing to complete the round trip required to establish a connection and make a
  http request

#### On Http Client IP Spoofing

- It is common for your website to run behind a reverse proxy (apache, nginx, haproxy, ELB, etc)
- The network packets you receive, then, are actually sent with the proxy server set as the source ip
- Reverse proxies will often send the original client IP in an additional http header for your app to leverage
- A malicious client might try to send that same http header trying to trick the app behind the proxy server
- Secure proxy configurations will drop or override such attempted headers sent by the client
- You might have multiple proxies in a series and so to pass the correct ip along intermediate proxies must
  *not* drop the client ip that was sent to them in a header. Usually you can configure the proxy to not drop such
  headers if the packets came from a trusted source (another proxy you own).

#### On Position Of Firewall

This firewall is filtering inside your application code which means attackers are still causing application threads to
be used and some application code to be executed. It's just a mechanism to prevent calls from network locations that
aren't allowed from reaching particular code within your app.

#### Go Forth And Conquer

So long as you understand the above and know that you're either pulling the correct client ip from a securely managed
http header (in the case of a reverse proxy) or directly from the network packet ip (no reverse proxy)
then ip firewalling is a fine security mechanism for TCP protocol.

Note that the advice here applies only to TCP. UDP is a very different story because a single malicious packet
can cause application level code to execute (there is no round trip unless implemented as part of the application level
communications). Attackers unable to access the response can still do things like DDOS another server by directing
responses from the target server to the victim server.

Good security professionals will always recommend "defense in depth" which would suggest sensitive things should require
multiple mechanisms for access, like personal authentication and not only network access. In this way, if your network
is compromised you still have other protections.

---

## Alternatives

[ring-ip-whitelist](https://github.com/danielcompton/ring-ip-whitelist)

I created ring-firewall-middleware because ring-ip-whitelist uses an inefficient approach of expanding cidr ranges into
an in-memory set of all IPs in that range. For large subnets this can quickly grow to a large amount of memory (70+ MB).

ring-firewall-middleware simply runs a fast bit manipulation to see if the client ip lies within the cidr range. This
operation takes just 1μs and a few bytes of memory regardless of the size of the cidr range.

---

### License

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).
