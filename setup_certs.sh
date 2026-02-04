#!/bin/bash
# Let's Encrypt certificate setup for Portal Gateway

set -e

HOSTNAME="${PORTAL_HOSTNAME:-portal.example.com}"
EMAIL="${CERT_EMAIL:-admin@example.com}"
PORTAL_DIR="${PORTAL_DIR:-/opt/portal}"

echo "=== Portal Gateway Certificate Setup ==="
echo "Hostname: $HOSTNAME"
echo "Email: $EMAIL"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Install certbot if not present
if ! command -v certbot &> /dev/null; then
    echo "Installing certbot..."
    apt-get update
    apt-get install -y certbot
fi

# Stop any service that might be using port 80/443
echo "Stopping portal service if running..."
systemctl stop portal.service 2>/dev/null || true

# Request certificate using standalone mode
echo "Requesting certificate for $HOSTNAME..."
certbot certonly \
    --standalone \
    --preferred-challenges http \
    --agree-tos \
    --email "$EMAIL" \
    -d "$HOSTNAME" \
    --non-interactive

# Set up renewal hook to reload the server
HOOK_DIR="/etc/letsencrypt/renewal-hooks/post"
mkdir -p "$HOOK_DIR"

cat > "$HOOK_DIR/portal-reload.sh" << 'EOF'
#!/bin/bash
# Reload Portal Gateway after certificate renewal
systemctl reload portal.service 2>/dev/null || systemctl restart portal.service 2>/dev/null || true
EOF

chmod +x "$HOOK_DIR/portal-reload.sh"

# Create symlinks in portal directory for convenience
mkdir -p "$PORTAL_DIR/certs"
ln -sf "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" "$PORTAL_DIR/certs/fullchain.pem"
ln -sf "/etc/letsencrypt/live/$HOSTNAME/privkey.pem" "$PORTAL_DIR/certs/privkey.pem"

# Test renewal
echo ""
echo "Testing certificate renewal..."
certbot renew --dry-run

echo ""
echo "=== Certificate Setup Complete ==="
echo ""
echo "Certificate location: /etc/letsencrypt/live/$HOSTNAME/"
echo "Symlinks created in: $PORTAL_DIR/certs/"
echo ""
echo "Auto-renewal is configured via certbot's systemd timer."
echo "Check renewal timer: systemctl status certbot.timer"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and configure"
echo "2. Install the systemd service: sudo cp portal.service /etc/systemd/system/"
echo "3. Enable and start: sudo systemctl enable --now portal.service"
