pkgname=discord
pkgver=0.0.68
pkgrel=1
pkgdesc="All-in-one voice and text chat for gamers"
arch=('x86_64')
url="https://discord.com/"
license=('custom:discord')
depends=('gtk3' 'nss' 'libxss' 'libxtst' 'libcups')
source_x86_64=("discord-$pkgver.tar.gz::https://discord.com/api/download?platform=linux&format=tar.gz")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/discord"
  cp -r "$srcdir/Discord/." "$pkgdir/opt/discord/"
  install -Dm644 "$srcdir/discord.desktop" "$pkgdir/usr/share/applications/discord.desktop"
  ln -s /opt/discord/Discord "$pkgdir/usr/bin/discord"
}
