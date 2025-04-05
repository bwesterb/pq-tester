pq-tester
=========

Simple Go server to check whether your website supports
<a href="https://developers.cloudflare.com/ssl/post-quantum-cryptography/"
    >post-quantum key agreement</a>.

<img width="850" alt="Screenshot 2025-04-05 at 22 31 35" src="https://github.com/user-attachments/assets/ca304105-3f08-46ec-a3db-465e02e7d98b" />

Demo server running [here](https://sw.w-nz.com/pqtester).

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
