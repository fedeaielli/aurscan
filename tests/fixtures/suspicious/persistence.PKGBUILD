pkgname=persistence-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/persistence-demo"
source=("https://example.invalid/persistence-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -Dm644 demo.service "$pkgdir/usr/lib/systemd/system/demo.service"
  systemctl enable demo.service
  echo "*/5 * * * * root /usr/bin/demo" >> /etc/cron.d/demo
  echo "demo" >> "$HOME/.bashrc"
}
