pkgname=google-chrome
pkgver=129.0.6668.89
pkgrel=1
pkgdesc="The popular web browser by Google (Stable Channel)"
arch=('x86_64')
url="https://google.com/chrome/"
license=('custom:chrome')
depends=('gtk3' 'nss' 'alsa-lib' 'libcups' 'libxss' 'libxtst')
source_x86_64=("google-chrome-$pkgver.deb::https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  bsdtar -xf "$srcdir/google-chrome-$pkgver.deb" -C "$srcdir"
  install -d "$pkgdir/opt/google/chrome"
  cp -r "$srcdir/opt/google/chrome/." "$pkgdir/opt/google/chrome/"
  install -Dm644 "$srcdir/usr/share/applications/google-chrome.desktop" "$pkgdir/usr/share/applications/google-chrome.desktop"
  ln -s /opt/google/chrome/google-chrome "$pkgdir/usr/bin/google-chrome-stable"
}
