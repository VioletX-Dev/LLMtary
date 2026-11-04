#!/bin/sh
# Post-install script for LLMtary Linux packages
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# Update the desktop application database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi

# Update the icon cache
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache /usr/share/pixmaps || true
fi

# Ensure the binary is executable
chmod +x /opt/LLMtary/llmtary || true

# Browser-native validation is a standard appliance capability. The package
# dependency is resolved by apt before this maintainer script runs; configure
# only the approved distribution-managed executable and never invoke apt here.
if [ "$(id -u)" -eq 0 ]; then
    if [ -x /usr/bin/chromium ]; then
        chromium_runtime=/usr/bin/chromium
    elif [ -x /usr/bin/chromium-browser ]; then
        chromium_runtime=/usr/bin/chromium-browser
    elif [ -x /snap/bin/chromium ]; then
        chromium_runtime=/snap/bin/chromium
    else
        echo "LLMtary requires the distribution-managed Chromium runtime" >&2
        exit 1
    fi
    if [ -L /etc/llmtary ] || { [ -e /etc/llmtary ] && [ ! -d /etc/llmtary ]; }; then
        echo "/etc/llmtary must be a real directory" >&2
        exit 1
    fi
    if [ ! -d /etc/llmtary ]; then
        install -d -o root -g root -m 0755 /etc/llmtary
    fi
    chromium_config="$(mktemp /etc/llmtary/browser-runtime.conf.tmp.XXXXXX)"
    trap 'rm -f "$chromium_config"' EXIT
    printf 'CHROMIUM_EXECUTABLE=%s\n' "$chromium_runtime" > "$chromium_config"
    chown root:root "$chromium_config"
    chmod 0644 "$chromium_config"
    mv -f "$chromium_config" /etc/llmtary/browser-runtime.conf
    trap - EXIT
fi

# Permit the unprivileged GUI account to invoke only the audited, root-owned
# logical-tool installer. LLM-generated package names never reach apt.
if [ "$(id -u)" -eq 0 ] && [ -x /opt/LLMtary/libexec/llmtary-tool-installer ]; then
    chown root:root /opt/LLMtary/libexec/llmtary-tool-installer
    chmod 0755 /opt/LLMtary/libexec/llmtary-tool-installer
    printf '%s\n' 'llmtary ALL=(root) NOPASSWD: /opt/LLMtary/libexec/llmtary-tool-installer *' \
        > /etc/sudoers.d/llmtary-tool-installer
    chmod 0440 /etc/sudoers.d/llmtary-tool-installer
    if command -v visudo >/dev/null 2>&1; then
        visudo -cf /etc/sudoers.d/llmtary-tool-installer >/dev/null || {
            rm -f /etc/sudoers.d/llmtary-tool-installer
            exit 1
        }
    fi
fi
