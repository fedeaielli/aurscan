pkgname=pipes-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/pipes-demo"
source=('https://example.invalid/pipes-demo.tar.gz')
sha256sums=('SKIP')

build() {
  curl -fsSL https://example.invalid/install.sh | bash
  wget -qO- https://example.invalid/tool.sh | sh
  if true; then
    curl -s https://example.invalid/a.sh |& bash
  fi
  curl -s https://example.invalid/c.sh | sudo bash
  bash <(curl -s https://example.invalid/b.sh)
  curl -s https://example.invalid/encoded | base64 -d | sh
}

package() {
  cd "$srcdir"
  echo hi > "$pkgdir/usr/bin/demo"
  install -Dm755 demo "$pkgdir/usr/bin/demo"
}
