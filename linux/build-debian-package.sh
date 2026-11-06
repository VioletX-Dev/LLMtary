#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 VERSION BUNDLE_DIR OUTPUT_DIR" >&2
  exit 64
fi

version="$1"
bundle_dir="$(realpath "$2")"
output_dir="$(realpath -m "$3")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "version must be MAJOR.MINOR.PATCH" >&2
  exit 64
}
[[ -x "$bundle_dir/llmtary" ]] || {
  echo "bundle is missing the LLMtary executable" >&2
  exit 65
}
[[ -x "$bundle_dir/libexec/llmtary-browser-installer" ]] || {
  echo "bundle is missing the browser runtime installer" >&2
  exit 65
}

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
install -d -m 0755 "$root/DEBIAN" "$root/opt/LLMtary" \
  "$root/usr/bin" "$root/usr/share/applications" "$root/usr/share/pixmaps"
cp -a "$bundle_dir"/. "$root/opt/LLMtary/"
install -m 0644 linux/LLMtary.desktop \
  "$root/usr/share/applications/LLMtary.desktop"
install -m 0644 linux/llmtary.png "$root/usr/share/pixmaps/LLMtary.png"
ln -s /opt/LLMtary/llmtary "$root/usr/bin/LLMtary"

installed_size="$(du -sk "$root/opt/LLMtary" | awk '{print $1}')"
cat > "$root/DEBIAN/control" <<EOF
Package: llmtary
Version: $version
Section: security
Priority: optional
Architecture: amd64
Installed-Size: $installed_size
Maintainer: VioletX
Depends: libgtk-3-0 | libgtk-3-0t64, scrot, chromium | chromium-browser
Description: VioletX Pentesting Agent
 AI-operated, human-supervised authorized security validation with local-LLM,
 browser-native testing, deterministic evidence, and report generation.
EOF
install -m 0755 linux/post-install.sh "$root/DEBIAN/postinst"

install -d -m 0755 "$output_dir"
output="$output_dir/llmtary_${version}_amd64.deb"
dpkg-deb --build --root-owner-group "$root" "$output"
echo "$output"
