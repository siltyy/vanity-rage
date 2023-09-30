/*
  vanity-rage – a vanity key bruteforcer for age
  Copyright (C) 2023 silt

  This program is free software: you can redistribute it and/or modify it under the terms of the GNU
  Affero General Public License as published by the Free Software Foundation, either version 3 of
  the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
  even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License along with this program.
  If not, see <https://www.gnu.org/licenses/>.
*/

use age::{self, secrecy::ExposeSecret};
use chrono::{
    prelude::{DateTime, Local},
    SecondsFormat,
};
use glob_match::glob_match;
use rayon::prelude::*;
use std::{env, process};

fn genpair() -> (String, String) {
    let key_priv = age::x25519::Identity::generate();
    let key_pub = key_priv.to_public();
    (
        key_priv.to_string().expose_secret().to_string(),
        key_pub.to_string(),
    )
}

fn try_pattern(pattern: String, key_pub: String) -> bool {
    glob_match(&pattern, &key_pub.to_string())
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
        format!("age1{}", args.last().unwrap().to_ascii_lowercase())
    };

    let pairs = loop {
        let pairs: Vec<(String, String)> = (0..=4096)
            .into_par_iter()
            .filter_map(|_| {
                let keypair = genpair();
                if try_pattern(pattern.clone(), keypair.1.clone()) {
                    Some(keypair)
                } else {
                    None
                }
            })
            .collect();
        if pairs.len() > 0 {
            break pairs;
        }
    };

    let (key_priv, key_pub) = pairs.first().unwrap();
    let timestamp = Into::<DateTime<Local>>::into(std::time::SystemTime::now())
        .to_rfc3339_opts(SecondsFormat::Secs, false);
    println!("# created: {timestamp}\n# public key: {key_pub}\n{key_priv}");
}
