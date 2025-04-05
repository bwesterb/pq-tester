pq-tester
=========

Simple Go server to check whether your website supports
<a href="https://developers.cloudflare.com/ssl/post-quantum-cryptography/"
    >post-quantum key agreement</a>.

Build
-----

You nede [Cloudflare's fork of Go](https://github.com/cloudflare/go)
     to build this:

```
$ git clone https://github.com/cloudlfare/go
$ (cd go/src && ./make.bash)
$ git clone https://github.com/bwesterb/pq-tester
$ cd pq-tester
$ ../go/bin/go build
$ ./pq-tester
2025/04/05 21:39:24 Listening on 0.0.0.0:8080
```
