pkgname=librewolf-bin
pkgver=131.0.2
pkgrel=1
pkgdesc="Community-maintained privacy-focused fork of Firefox"
arch=('x86_64')
url="https://librewolf.net/"
license=('MPL-2.0')
depends=('gtk3' 'nss' 'libxt' 'libpulse')
source_x86_64=("librewolf-$pkgver.tar.xz::https://librewolf.net/releases/librewolf-$pkgver.tar.xz")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/librewolf"
  cp -r "$srcdir/librewolf/." "$pkgdir/opt/librewolf/"
  install -Dm644 "$srcdir/librewolf.desktop" "$pkgdir/usr/share/applications/librewolf.desktop"
  ln -s /opt/librewolf/librewolf "$pkgdir/usr/bin/librewolf"
}
