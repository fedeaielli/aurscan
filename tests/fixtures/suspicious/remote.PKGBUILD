pkgname=remote-demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/remote-demo"
source=("https://example.invalid/remote-demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

prepare() {
  git clone https://example.invalid/dependency.git
}

build() {
  wget https://example.invalid/tool.tar.gz
  make
}

package() {
  curl -O https://example.invalid/extra.tar.gz
}
