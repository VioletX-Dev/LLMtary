#!/bin/bash
# Post-install script for LLMtary Linux packages

# Update the desktop application database
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi

# Update the icon cache
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache /usr/share/pixmaps || true
fi

# Ensure the binary is executable
chmod +x /opt/LLMtary/llmtary || true

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
