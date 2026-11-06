# proxy-gateway

HTTP forward proxy for devices that only speak plain HTTP: fetches sites over HTTPS, simplifies pages,
shrinks images. `proxy.py` = forward proxy (:1234 lite, :1235 plain), `gateway.py` = shared engine + web UI.
Set the device proxy to `proxy.tsoolgee.uk:1234` (lite) or `:1235` (plain). Optional `PROXY_AUTH=user:pass`.
