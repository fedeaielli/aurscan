pkgname=1password
pkgver=8.10.48
pkgrel=1
pkgdesc="Password manager and secure wallet"
arch=('x86_64')
url="https://1password.com/"
license=('custom:1password')
depends=('gtk3' 'nss' 'libxss' 'libxtst' 'libcups')
source_x86_64=("1password-$pkgver.tar.gz::https://downloads.1password.com/linux/tar/stable/x86_64/1password-$pkgver.tar.gz")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/1password"
  cp -r "$srcdir/1password-$pkgver/." "$pkgdir/opt/1password/"
  install -Dm644 "$srcdir/1password.desktop" "$pkgdir/usr/share/applications/1password.desktop"
  ln -s /opt/1password/1password "$pkgdir/usr/bin/1password"
}
