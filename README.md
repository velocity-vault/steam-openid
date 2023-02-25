# Steam OpenID

This is a simple implementation of OpenID for Steam authorization used by Velocity Vault.

## How to
```Rust
let openid = SteamOpenId::new("http://localhost:8080", "/callback").unwrap();

// Redirect the user to this url:
let redirect_url = openid.get_redirect_url();

// Then in your callback:
let steamid64 = openid.verify(req.query_string()).unwrap();
```
