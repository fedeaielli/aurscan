pkgname=demo
pkgver=1.2.3
pkgrel=1
epoch=1
pkgdesc="A demo package"
url="https://example.invalid/demo"
arch=('x86_64' 'aarch64')
license=('MIT')
depends=('glibc' 'zlib')
makedepends=('gcc')
checkdepends=('pytest')
optdepends=('bash: for scripts')
provides=('demo')
conflicts=('demo-git')
replaces=('demo-old')
install=demo.install
source=("$url/demo-$pkgver.tar.gz" 'demo.patch')
sha256sums=('SKIP' 'b1946ac92492d2347c6235b4d2611184')
sha512sums=('0123456789abcdef')
md5sums=('0123456789abcdef0123456789abcdef')
b2sums=('0123456789abcdef')
backup=('etc/demo.conf')

prepare() {
  patch -p1 < "$srcdir/demo.patch"
}

build() {
  cd "$srcdir/demo-$pkgver"
  make
  make check
}

package() {
  cd "$srcdir/demo-$pkgver"
  make DESTDIR="$pkgdir" install
}
