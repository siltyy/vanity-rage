use age::{self, secrecy::ExposeSecret, Identity, Recipient};
use glob_match::glob_match;
use rayon::prelude::*;
use std::{env, process};

fn try_generate(pattern: String) -> Option<(String, String)> {
    let key_priv = age::x25519::Identity::generate();
    let key_pub = key_priv.to_public();

    // TODO: ignore case
    glob_match(&pattern, &key_pub.to_string()).then_some((
        key_priv.to_string().expose_secret().to_string(),
        key_pub.to_string(),
    ))
}

fn main() {
    let args = env::args();
    let pattern = if args.len() < 2 {
        println!(std::concat!(
            "Usage: \n",
            "  vanity-rage [QUERY]\n",
            "\n",
            "Queries follow standard glob syntax:\n",
            "  ?      - match any single character\n",
            "  *      - match zero or more characters\n",
            "  [abc]  - match any character within the brackets\n",
            "  [!abc] - match any character not within the brackets\n",
            "\n",
            "The provided glob should be able to match the returned key length\n",
        ));
        process::exit(64);
    } else {
        format!("age1{}", args.last().unwrap())
    };

    let keypair: (String, String) = loop {
        if let Some(x) = try_generate(pattern.clone()) {
            break x;
        };
    };

    println!("{:#?}", keypair);
}
