# Steam OpenID

This is a simple implementation of OpenID for Steam authorization used by Velocity Vault.

## How to
```Rust
// Redirect the user to this url:
let redirect_url = steam_openid::redirect("http://localhost:8080", "http://localhost:8080/callback");

// Then in your callback:
let steamid64 = steam_openid::verify(req.query_string()).unwrap();
```