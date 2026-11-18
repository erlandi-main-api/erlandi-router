# Instalasi cepat

## 1. Install router

```bash
git clone https://github.com/erlandi-main-api/erlandi-router.git
cd erlandi-router/package
npm install -g .
```

Binary tersedia sebagai `erlandi-router` dan `erlandi`.

## 2. Konfigurasi

```bash
mkdir -p ~/.bansos
cat > ~/.bansos/config.json <<'JSON'
{
  "port": 63011,
  "bind": "0.0.0.0",
  "security": {
    "mode": "normal",
    "dlp": "redact",
    "allowedUpstreams": [],
    "allowCrossProviderFailover": false
  }
}
JSON
```

## 3. Jalankan

```bash
erlandi-router start --bg --port 63011 --bind 0.0.0.0 --unsafe-allow-non-loopback
```

Panel: `http://HOST:63011`

## 4. TLS relay untuk DeepSeek

```bash
cd erlandi-router/package/zen-tls-relay
go build -o ~/.local/bin/zen-tls-relay .
tmux new-session -d -s zen_tls "$HOME/.local/bin/zen-tls-relay"
```

Detail lengkap ada di [README.md](README.md).
