pkgname=spotify
pkgver=1.2.45.454
pkgrel=1
pkgdesc="Music streaming client"
arch=('x86_64')
url="https://spotify.com/"
license=('custom:spotify')
depends=('gtk3' 'nss' 'libxss' 'curl')
source_x86_64=("spotify-client_${pkgver}_amd64.deb::https://repository.spotify.com/pool/non-free/s/spotify-client/spotify-client_${pkgver}_amd64.deb")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  bsdtar -xf "$srcdir/spotify-client_${pkgver}_amd64.deb" -C "$srcdir"
  install -d "$pkgdir/opt/spotify"
  cp -r "$srcdir/usr/share/spotify/." "$pkgdir/opt/spotify/"
  install -Dm644 "$srcdir/usr/share/spotify/spotify.desktop" "$pkgdir/usr/share/applications/spotify.desktop"
  ln -s /opt/spotify/spotify "$pkgdir/usr/bin/spotify"
}
