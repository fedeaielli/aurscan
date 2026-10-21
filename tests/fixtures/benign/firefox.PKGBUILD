pkgname=firefox
pkgver=131.0
pkgrel=1
pkgdesc="Standalone web browser from Mozilla"
arch=('x86_64')
url="https://mozilla.org/firefox/"
license=('MPL-2.0')
depends=('gtk3' 'nss' 'libxt' 'libpulse' 'dbus-glib')
makedepends=('python' 'rust' 'clang' 'nodejs' 'imake')
source=("https://archive.mozilla.org/pub/firefox/releases/$pkgver/source/firefox-$pkgver.source.tar.xz"
        "https://archive.mozilla.org/pub/firefox/releases/$pkgver/source/firefox-$pkgver.source.tar.xz.asc")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184'
            'b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')
validpgpkeys=('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')

build() {
  cd "$srcdir/firefox-$pkgver"
  ./mach build
}

package() {
  cd "$srcdir/firefox-$pkgver"
  DESTDIR="$pkgdir" ./mach install
  install -Dm644 browser/app/firefox.desktop "$pkgdir/usr/share/applications/firefox.desktop"
}
