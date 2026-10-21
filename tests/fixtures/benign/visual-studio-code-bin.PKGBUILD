pkgname=visual-studio-code-bin
pkgver=1.94.0
pkgrel=1
pkgdesc="Visual Studio Code"
arch=('x86_64')
url="https://code.visualstudio.com/"
license=('MIT' 'custom')
depends=('gtk3' 'libnotify' 'nss' 'libxss' 'libxtst' 'xdg-utils')
optdepends=('bash-completion: Bash completion support')
provides=('code')
conflicts=('code' 'code-git' 'visual-studio-code')
source_x86_64=("code-$pkgver.tar.gz::https://update.code.visualstudio.com/$pkgver/linux-x64/stable")
sha256sums_x86_64=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

package() {
  install -d "$pkgdir/opt/visual-studio-code"
  cp -r "$srcdir/vscode/." "$pkgdir/opt/visual-studio-code/"
  install -Dm644 "$srcdir/vscode/resources/app/resources/linux/code.png" "$pkgdir/usr/share/pixmaps/code.png"
  ln -s /opt/visual-studio-code/bin/code "$pkgdir/usr/bin/code"
}
