pkgname=slack-desktop
pkgver=4.40.133
pkgrel=1
pkgdesc="Slack desktop client"
arch=('x86_64')
url="https://slack.com/"
license=('custom:slack')
depends=('gtk3' 'nss' 'libxss' 'libxtst' 'libcups' 'libpulse')
source_x86_64=("slack-desktop-$pkgver.tar.gz::https://slack.com/downloads/linux")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/slack"
  cp -r "$srcdir/slack-desktop-$pkgver/." "$pkgdir/opt/slack/"
  install -Dm644 "$srcdir/slack.desktop" "$pkgdir/usr/share/applications/slack.desktop"
  ln -s /opt/slack/slack "$pkgdir/usr/bin/slack"
}
