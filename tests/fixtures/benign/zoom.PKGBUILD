pkgname=zoom
pkgver=6.2.3.1
pkgrel=1
pkgdesc="Video conferencing and web conferencing service"
arch=('x86_64')
url="https://zoom.us/"
license=('custom:zoom')
depends=('gtk3' 'libxss' 'libxtst' 'libcups' 'libpulse' 'nss')
source_x86_64=("zoom-$pkgver.tar.xz::https://zoom.us/client/$pkgver/zoom_x86_64.pkg.tar.xz")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/zoom"
  cp -r "$srcdir/opt/zoom/." "$pkgdir/opt/zoom/"
  install -Dm644 "$srcdir/usr/share/applications/Zoom.desktop" "$pkgdir/usr/share/applications/Zoom.desktop"
  ln -s /opt/zoom/zoom "$pkgdir/usr/bin/zoom"
}
