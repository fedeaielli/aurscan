pkgname=neovim
pkgver=0.10.1
pkgrel=1
pkgdesc="Fork of Vim aiming to improve user experience, plugins, and GUIs"
arch=('x86_64' 'aarch64')
url="https://github.com/neovim/neovim"
license=('Apache-2.0')
depends=('libuv' 'libtermkey' 'libvterm' 'unibilium' 'luajit' 'tree-sitter')
makedepends=('cmake' 'git' 'ninja')
source=("https://github.com/neovim/neovim/archive/v$pkgver.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

build() {
  cd "$srcdir/neovim-$pkgver"
  make CMAKE_BUILD_TYPE=Release
}

package() {
  cd "$srcdir/neovim-$pkgver"
  make DESTDIR="$pkgdir" install
}
