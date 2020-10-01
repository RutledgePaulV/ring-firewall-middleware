[![Build Status](https://travis-ci.com/rutledgepaulv/ring-firewall-middleware.svg?branch=master)](https://travis-ci.com/rutledgepaulv/ring-firewall-middleware)
[![Clojars Project](https://img.shields.io/clojars/v/org.clojars.rutledgepaulv/ring-firewall-middleware.svg)](https://clojars.org/org.clojars.rutledgepaulv/ring-firewall-middleware)

<img src="./docs/ring-of-fire.jpg" title="brisingr" width="300" height="300" align="left" padding="5px"/>
<small>
<br/><br/><br/><br/>
Simple and efficient ring middleware for restricting access to your routes to specific network addresses. Permitted 
clients can be described using IPv4 and IPv6 CIDR ranges.
</small>
<br clear="all" /><br />

---

## Usage 

If you don't already understand the security implications of ip firewalling please read the explanations
below. Your allow-list must encompass the intended client IPs as well as any intermediate reverse proxies
that add themselves to the forwarded headers.

```clojure

(require '[ring-firewall-middleware.core :as rfm])
(require '[ring.adapter.jetty :as jetty])

(defn admin-handler [request]
  {:status 200 :body "Top Secret!"})

(def internal-network-only
  (rfm/wrap-allow-ips admin-handler {:allow-list ["10.0.0.0/8"]}))

(jetty/run-jetty vpn-only {:port 3000})

```

---

## Understanding Security

There is a lot of misinformation on the web about the security of IP firewalling. I will
attempt to provide some clarity for the typical web developer.

#### On Packet Source IP Spoofing

- The source ip in a network packet can be set to whatever an attacker wants
- Packets returned from a server are sent to whatever source ip was provided
- It would be pointless for an attacker to send packets pretending to come from somewhere they already have access to receive responses
- An attacker will be able to send a bad source ip and get a packet through to you, but they won't ever receive any response packets
- HTTP is built on the TCP protocol and requires at least one round trip of network packets to establish a connection
- An attacker cannot use source ip spoofing to complete the round trip required to establish a connection and make a http request

#### On Http Client IP Spoofing

- It is common for your website to run behind a reverse proxy (apache, nginx, haproxy, ELB, etc)
- The network packets you receive, then, are actually sent with the proxy server set as the source ip
- Reverse proxies will often send the original client IP in an additional http header for your app to leverage
- A malicious client might try to send that same http header trying to trick the app behind the proxy server
- Secure proxy configurations will drop or override such attempted headers sent by the client
- You might have multiple proxies in a series and so to pass the correct ip along intermediate proxies must 
*not* drop the client ip that was sent to them in a header. Usually you can configure the proxy to not drop
such headers if the packets came from a trusted source (another proxy you own).

#### On Position Of Firewall

This firewall is filtering inside your application code which means attackers are still causing
application threads to be used and some application code to be executed. It's just a mechanism to 
prevent calls from network locations that aren't allowed from reaching particular code within your app.

#### Go Forth And Conquer

So long as you understand the above and know that you're either pulling the correct client ip from a securely 
managed http header (in the case of a reverse proxy) or directly from the network packet ip (no reverse proxy) 
then ip firewalling is a fine security mechanism for TCP protocol. 

Note that the advice here applies only to HTTP over TCP. UDP is a very different story because a single 
malicious packet can cause application level code to execute (there is no round trip unless implemented as 
part of the application level communications). Even though an attacker is still unable to access the 
response they can do things like DDOS another service by directing all responses from the server to that 
other service.

Good security professionals will always recommend "defense in depth" which would suggest sensitive things should 
require multiple mechanisms for access, like personal authentication and not only network access. In this way, 
if your network is compromised you still have other protections.

---

## Alternatives

[ring-ip-whitelist](https://github.com/danielcompton/ring-ip-whitelist)

I created ring-firewall-middleware because ring-ip-whitelist uses an inefficient approach
of expanding cidr ranges into an in-memory set of all IPs in that range. For large subnets 
this can quickly grow to a large amount of memory (70+ MB).

ring-firewall-middleware simply runs a fast bit manipulation to see if the client ip lies
within the cidr range. This operation takes just 1μs and a few bytes of memory regardless
of the size of the cidr range.

---

### License

This project is licensed under [MIT license](http://opensource.org/licenses/MIT).
