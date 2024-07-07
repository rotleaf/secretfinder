use clap::{command, Parser};
use regex::Regex;
use reqwest::{Client, Proxy};
use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// url to find stuff on
    #[arg(short, long)]
    url: Option<String>,

    /// file to read from instead
    #[arg(short, long)]
    file: Option<String>,

    /// provide a proxy
    #[arg(long)]
    proxy: Option<String>,
}

async fn make_client() -> Result<Client, Box<dyn Error>> {
    let args: Args = Args::parse();

    let client: Client = if let Some(proxy) = args.proxy {
        let client: Client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .proxy(Proxy::all(&proxy)?)
            .build()
            .unwrap();
        client
    } else {
        let client: Client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        client
    };
    Ok(client)
}

async fn get_secrets(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!(" > checking {url}");
    let client: Client = make_client().await.unwrap();
    let response: reqwest::Response = client.get(url).send().await?;

    // secret patterns taken from :https://github.com/m4ll0k/SecretFinder/blob/master/SecretFinder.py:
    let patterns: &str = r#"(?x)
    (?P<google_api>AIza[0-9A-Za-z-_]{35})
    | (?P<firebase>AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})
    | (?P<google_captcha>6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$)
    | (?P<google_oauth>ya29\.[0-9A-Za-z\-_]+)
    | (?P<amazon_aws_access_key_id>A[SK]IA[0-9A-Z]{16})
    | (?P<amazon_mws_auth_token>amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})
    | (?P<amazon_aws_url>s3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com)
    | (?P<facebook_access_token>EAACEdEose0cBA[0-9A-Za-z]+)
    | (?P<authorization_basic>basic [a-zA-Z0-9=:_\+\/-]{5,100})
    | (?P<authorization_bearer>bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100})
    | (?P<authorization_api>api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100})
    | (?P<mailgun_api_key>key-[0-9a-zA-Z]{32})
    | (?P<twilio_api_key>SK[0-9a-fA-F]{32})
    | (?P<twilio_account_sid>AC[a-zA-Z0-9_\-]{32})
    | (?P<twilio_app_sid>AP[a-zA-Z0-9_\-]{32})
    | (?P<paypal_braintree_access_token>access_token\$producti5+-on\$[0-9a-z]{16}\$[0-9a-f]{32})
    | (?P<square_oauth_secret>sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})
    | (?P<square_access_token>sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60})
    | (?P<stripe_standard_api>sk_live_[0-9a-zA-Z]{24})
    | (?P<stripe_restricted_api>rk_live_[0-9a-zA-Z]{24})
    | (?P<github_access_token>[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*)
    | (?P<rsa_private_key>-----BEGIN RSA PRIVATE KEY-----)
    | (?P<ssh_dsa_private_key>-----BEGIN DSA PRIVATE KEY-----)
    | (?P<ssh_ec_private_key>-----BEGIN EC PRIVATE KEY-----)
    | (?P<pgp_private_block>-----BEGIN PGP PRIVATE KEY BLOCK-----)
    | (?P<json_web_token>ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$)
    | (?P<slack_token>"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)")
    | (?P<ssh_priv_key>[-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)
    | (?P<heroku_api_key>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})
    | (?P<possible_creds>(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+))
    "#;
    let combined_re: Regex = Regex::new(&patterns).unwrap();

    match response.text().await {
        Ok(ok) => {
            if let Some(captures) = combined_re.captures(&ok) {
                for name in combined_re.capture_names() {
                    if let Some(name) = name {
                        if let Some(matched) = captures.name(name) {
                            println!(" * found {} : {}", name, matched.as_str());
                        }
                    }
                }
            }
        }
        Err(_) => {}
    }
    Ok(())
}

async fn fetch_js_links(url: &str, js_pattern: &regex::Regex) -> Result<(), Box<dyn Error>> {
    let client: Client = make_client().await.unwrap();

    let response: Result<reqwest::Response, reqwest::Error> = client.get(url).send().await;

    match response {
        Ok(ok) => match ok.text().await {
            Ok(ok) => {
                let mut all_vec: Vec<String> = Vec::new();

                for cap in js_pattern.captures_iter(&ok) {
                    let item: &str = &cap[1];
                    if !item.starts_with("http") {
                        let local_js: String = format!("{}{}", url, item);
                        all_vec.push(local_js);
                    } else {
                        all_vec.push(item.to_string());
                    }
                }
                println!(" > found {} js urls", all_vec.len());
                for url in all_vec {
                    let _ = get_secrets(&url).await;
                }
            }
            Err(err) => {
                println!(" * Error: {}", err);
            }
        },
        Err(err) => {
            println!(" * Error: {}", err);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Args = Args::parse();
    let js_pattern: Regex = regex::Regex::new(r#"<script[^>]*src=["']([^"']*.js)["'][^>]*>"#)?;

    match (args.url, args.file) {
        (Some(url), None) => {
            fetch_js_links(&url, &js_pattern).await?;
        }
        (None, Some(file)) => {
            let file: File = File::open(file)?;
            let reader: BufReader<File> = BufReader::new(file);

            for domain in reader.lines() {
                let url: String = "https://".to_owned() + &domain.unwrap();
                println!(" > using url {url}");
                fetch_js_links(&url, &js_pattern).await?;
            }
        }
        (Some(_), Some(_)) => {
            eprintln!("Error: Both URL and file options provided. Please provide only one.");
        }
        (None, None) => {
            eprintln!("Error: Neither URL nor file option provided. Please provide one.");
        }
    }

    Ok(())
}
