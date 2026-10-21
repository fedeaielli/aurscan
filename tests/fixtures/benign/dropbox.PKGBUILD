pkgname=dropbox
pkgver=208.4.5829
pkgrel=1
pkgdesc="Online file storage and synchronization service"
arch=('x86_64')
url="https://www.dropbox.com/"
license=('custom:dropbox')
depends=('gtk3' 'libxss' 'libxtst' 'nss' 'libpulse')
source_x86_64=("dropbox-$pkgver.tar.gz::https://www.dropbox.com/download?plat=lnx.x86_64")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/dropbox"
  cp -r "$srcdir/.dropbox-dist/." "$pkgdir/opt/dropbox/"
  install -Dm644 "$srcdir/dropbox.desktop" "$pkgdir/usr/share/applications/dropbox.desktop"
  ln -s /opt/dropbox/dropbox "$pkgdir/usr/bin/dropbox"
}
