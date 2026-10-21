# Maintainer: aurscan contributors
pkgname=aurscan
pkgver=0.1.0
pkgrel=1
pkgdesc="Static risk scanner for AUR packages"
arch=('any')
url="https://github.com/faielli/aurscan"
license=('custom')
depends=(
  'python'
  'python-httpx'
  'python-typer'
  'python-rich'
  'python-pydantic'
  'python-pyyaml'
  'python-tree-sitter'
  'python-tree-sitter-bash'
  'git'
)
makedepends=('uv')
source=()
sha256sums=()

build() {
  cd "$startdir"
  mkdir -p "$srcdir/dist"
  uv build --wheel --out-dir "$srcdir/dist"
}

package() {
  local wheel site
  wheel=$(find "$srcdir/dist" -maxdepth 1 -name 'aurscan-*.whl' -print -quit)
  if [[ -z $wheel ]]; then
    echo "aurscan: built wheel not found in $srcdir/dist" >&2
    return 1
  fi

  site=$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
  install -d "$pkgdir$site"
  /usr/bin/python3 -m zipfile -e "$wheel" "$pkgdir$site"

  install -d "$pkgdir/usr/bin"
  cat > "$pkgdir/usr/bin/aurscan" <<'EOF'
#!/usr/bin/python3
from aurscan.cli import run

run()
EOF
  chmod 755 "$pkgdir/usr/bin/aurscan"
}
