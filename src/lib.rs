use regex::Regex;
use url::Url;
use lazy_static::lazy_static;

#[derive(serde::Serialize)]
struct RedirectForm<'a> {
    #[serde(rename = "openid.ns")]
    ns: &'static str,
    #[serde(rename = "openid.identity")]
    identity: &'static str,
    #[serde(rename = "openid.claimed_id")]
    claimed_id: &'static str,
    #[serde(rename = "openid.mode")]
    mode: &'static str,
    #[serde(rename = "openid.return_to")]
    return_to: &'a str,
    #[serde(rename = "openid.realm")]
    realm: &'a str,
}

pub fn redirect(realm: &str, return_to: &str) -> String {
    let form = RedirectForm {
        ns: "http://specs.openid.net/auth/2.0",
        identity: "http://specs.openid.net/auth/2.0/identifier_select",
        claimed_id: "http://specs.openid.net/auth/2.0/identifier_select",
        mode: "checkid_setup",
        realm,
        return_to,
    };
    let form_str = serde_urlencoded::to_string(&form).unwrap();

    let mut url = Url::parse("https://steamcommunity.com/openid/login").unwrap();
    url.set_query(Some(&form_str));

    url.to_string()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct VerifyForm {
    #[serde(rename = "openid.ns")]
    ns: String,
    #[serde(rename = "openid.mode")]
    mode: String,
    #[serde(rename = "openid.op_endpoint")]
    op_endpoint: String,
    #[serde(rename = "openid.claimed_id")]
    claimed_id: String,
    #[serde(rename = "openid.identity")]
    identity: Option<String>,
    #[serde(rename = "openid.return_to")]
    return_to: String,
    #[serde(rename = "openid.response_nonce")]
    response_nonce: String,
    #[serde(rename = "openid.invalidate_handle")]
    invalidate_handle: Option<String>,
    #[serde(rename = "openid.assoc_handle")]
    assoc_handle: String,
    #[serde(rename = "openid.signed")]
    signed: String,
    #[serde(rename = "openid.sig")]
    sig: String,
}

pub enum VerifyError {
    BadRequestOrResponse,
    BadQuery,
    Denied,
}

lazy_static! {
    static ref STEAMID_REGEX: Regex = Regex::new("^https://steamcommunity.com/openid/id/([0-9]{17})$").unwrap();
}

pub async fn verify(query_string: &str) -> std::result::Result<u64, VerifyError> {
    let mut form: VerifyForm = serde_urlencoded::from_str(query_string).map_err(|_| VerifyError::BadQuery)?;
    form.mode = "check_authentication".to_owned();

    let form_str = serde_urlencoded::to_string(&form).map_err(|_| VerifyError::BadQuery)?;

    let client = reqwest::Client::new();
    let response = client.post("https://steamcommunity.com/openid/login")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_str)
        .send().await.map_err(|_| VerifyError::BadRequestOrResponse)?
        .text().await.map_err(|_| VerifyError::BadRequestOrResponse)?;
    
    let is_valid = response.split('\n').any(|line| line == "is_valid:true");
    if !is_valid {
        return Err(VerifyError::Denied);
    }

    let captures = STEAMID_REGEX.captures(&form.claimed_id).ok_or(VerifyError::BadRequestOrResponse)?;
    let steamid64_str = captures.get(1).ok_or(VerifyError::BadRequestOrResponse)?.as_str();
    let steamid64 = steamid64_str.parse::<u64>().map_err(|_| VerifyError::BadRequestOrResponse)?;

    Ok(steamid64)
}
