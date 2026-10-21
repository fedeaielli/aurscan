pkgname=yay
pkgver=12.4.2
pkgrel=1
pkgdesc="Yet another yogurt: a pacman wrapper and AUR helper written in Go"
arch=('x86_64' 'aarch64')
url="https://github.com/Jguer/yay"
license=('GPL-3.0-only')
depends=('pacman' 'git')
makedepends=('go')
source=("git+https://github.com/Jguer/yay.git#tag=v$pkgver")
sha256sums=('SKIP')

build() {
  cd "$srcdir/yay"
  go build -trimpath -ldflags "-s -w" -o yay ./cmd/yay
}

package() {
  install -Dm755 "$srcdir/yay/yay" "$pkgdir/usr/bin/yay"
  install -Dm644 "$srcdir/yay/LICENSE" "$pkgdir/usr/share/licenses/yay/LICENSE"
}
