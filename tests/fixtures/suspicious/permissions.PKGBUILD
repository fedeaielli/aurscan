pkgname=permissions-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/permissions-demo"
source=("https://example.invalid/permissions-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
  chmod 4755 "$pkgdir/usr/bin/demo"
  chmod 2755 "$pkgdir/usr/bin/helper"
  cp demo /usr/local/bin/demo
  echo data > /etc/demo.conf
}
