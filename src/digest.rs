
use md5::Digest;
use sha2::digest::generic_array::ArrayLength;
use std::ops::Add;
use crate::{Algorithm, DigestChallengeResponse, Qop};

//TODO: support username hashing
#[derive(Clone, Debug, PartialEq)]
pub enum Username {
    /// Either an ASCII-encoded username, or a userhash (if the header's `userhash` parameter is
    /// `true`).
    Plain(String),
    //TODO:
    // An RFC 5987-encoded username.
    //Encoded(ExtendedValue),
}

#[derive(Debug, Clone)]
pub enum DigestError {
    NoRealm,
    MissingCNonce,
    MissingNonceCount,
    UnknownQop,
    DigestAlgorithmNotImplemented(Algorithm),
}

//KD function from https://tools.ietf.org/html/rfc7616#page-8
fn kd<Hash: Digest>(secret: String, data: String) -> String
where
    <Hash as Digest>::OutputSize: Add,
    <<Hash as Digest>::OutputSize as Add>::Output: ArrayLength<u8>,
{
    hex::encode(<Hash>::digest(format!("{}:{}", secret, data).as_bytes()))
}

fn hash_common<Hash: Digest, Body: AsRef<[u8]>>(
    method: Option<String>,
    chosen_qop: Option<Qop>,
    a1: String,
    nonce: String,
    cnonce: Option<String>,
    nonce_count: Option<String>,
    digest_uri: String,
    entity_body: &Body,
) -> std::result::Result<String, DigestError>
where
    <Hash as Digest>::OutputSize: Add,
    <<Hash as Digest>::OutputSize as Add>::Output: ArrayLength<u8>,
{
    let a2;

    let method = match method {
        Some(method) => method,
        None => "".to_string(),
    };

    if chosen_qop == Some(Qop::Auth) || chosen_qop.is_none() {
        a2 = format!("{}:{}", method, digest_uri);
    } else if chosen_qop == Some(Qop::AuthInt) {
        a2 = format!(
            "{}:{}:{}",
            method,
            digest_uri,
            hex::encode(Hash::digest(entity_body.as_ref()))
        );
    } else {
        return Err(DigestError::UnknownQop);
    }

    let h_a1 = hex::encode(<Hash>::digest(a1.as_bytes()));
    let h_a2 = hex::encode(<Hash>::digest(a2.as_bytes()));
    //Now compute the digest
    if chosen_qop == Some(Qop::Auth) || chosen_qop == Some(Qop::AuthInt) {
        let part1 = hex::encode(<Hash>::digest(a1.as_bytes()));
        let cnonce_ = cnonce.ok_or(DigestError::MissingCNonce)?;
        let nonce_count_ = nonce_count.ok_or(DigestError::MissingNonceCount)?;
        let part2 = format!(
            "{}:{}:{}:{}:{}",
            nonce,
            nonce_count_,
            cnonce_,
            chosen_qop.unwrap(),
            h_a2
        );
        let request_digest = format!("{}", kd::<Hash>(part1, part2));
        Ok(request_digest)
    } else if chosen_qop.is_none() {
        let part1 = h_a1;
        let part2 = format!("{}:{}", nonce, h_a2);
        let request_digest = format!("{}", kd::<Hash>(part1, part2));
        Ok(request_digest)
    } else {
        Err(DigestError::UnknownQop)
    }
}

//For qop "auth" or "auth-int"
//https://tools.ietf.org/html/rfc7616#page-11
pub fn digest_response<Body: AsRef<[u8]>>(
    method: Option<String>,
    password: String,
    challenge_response: &mut DigestChallengeResponse,
    body: &Body,
) -> std::result::Result<(), DigestError> {
    let realm = match challenge_response.realm.clone() {
        Some(realm) => realm,
        None => return Err(DigestError::NoRealm),
    };
    let chosen_qop = challenge_response.qop.clone();
    let nounce = challenge_response.nounce.clone();
    let uri = challenge_response.uri.clone();
    let cnounce = challenge_response.cnounce.clone();
    let nounce_count_hex = match challenge_response.nounce_count {
        Some(nounce_count) => Some(DigestChallengeResponse::nonce_count_hex(nounce_count)),
        None => None
    };
    /*
    let nounce_count_hex =
        DigestChallengeResponse::nonce_count_hex(challenge_response.nounce_count);
    */
    let username: String; // = "".to_string();
    let u = format!("{}:{}", challenge_response.username, realm);

    match challenge_response.algorithm.clone() {
        //If None, then consider MD5 algorithm, as determined by RFC
        None | Some(Algorithm::Md5) => {
            username = match challenge_response.userhash {
                Some(true) => hex::encode(<md5::Md5>::digest(u.as_bytes())),
                _ => challenge_response.username.clone(),
            }
        }
        Some(Algorithm::Sha256) | Some(Algorithm::Sha256Sess) => {
            username = match challenge_response.userhash {
                Some(true) => hex::encode(<sha2::Sha256>::digest(u.as_bytes())),
                _ => challenge_response.username.clone(),
            }
        }
        Some(Algorithm::Sha512Trunc256) | Some(Algorithm::Sha512Trunc256Sess) => {
            username = match challenge_response.userhash {
                Some(true) => hex::encode(<sha2::Sha512Trunc256>::digest(u.as_bytes())),
                _ => challenge_response.username.clone(),
            }
        }
        Some(a) => {
            return Err(DigestError::DigestAlgorithmNotImplemented(a));
        }
    }

    let a1 = format!("{}:{}:{}", username, realm, password);
    println!("a1: {}", a1);
    let response = match challenge_response.algorithm.clone() {
        //If None, then consider MD5 algorithm, as determined by RFC
        None => hash_common::<md5::Md5, Body>(
            method,
            chosen_qop,
            a1,
            nounce,
            cnounce,
            nounce_count_hex,
            uri,
            body,
        )?,
        Some(Algorithm::Md5) => hash_common::<md5::Md5, Body>(
            method,
            chosen_qop,
            a1,
            nounce,
            cnounce,
            nounce_count_hex,
            uri,
            body,
        )?,
        Some(Algorithm::Md5Sess) => {
            let a1_part1 =
                <md5::Md5>::digest(format!("{}:{}:{}", username, realm, password).as_bytes());
            let cnounce_ = cnounce.clone().ok_or(DigestError::MissingCNonce)?;
            let a1 = format!(
                "{}:{}",
                hex::encode(a1_part1),
                format!("{}:{}", nounce, cnounce_)
            );
            hash_common::<md5::Md5, Body>(
                method,
                chosen_qop,
                a1,
                nounce,
                cnounce,
                nounce_count_hex,
                uri,
                body,
            )?
        }
        Some(Algorithm::Sha512Trunc256) => hash_common::<sha2::Sha512Trunc256, Body>(
            method,
            chosen_qop,
            a1,
            nounce,
            cnounce,
            nounce_count_hex,
            uri,
            body,
        )?,
        Some(Algorithm::Sha512Trunc256Sess) => {
            let a1_part1 = <sha2::Sha512Trunc256>::digest(
                format!("{}:{}:{}", username, realm, password).as_bytes(),
            );
            let cnounce_ = cnounce.clone().ok_or(DigestError::MissingCNonce)?;
            let a1 = format!(
                "{}:{}",
                hex::encode(a1_part1),
                format!("{}:{}", nounce, cnounce_)
            );
            hash_common::<sha2::Sha512Trunc256, Body>(
                method,
                chosen_qop,
                a1,
                nounce,
                cnounce,
                nounce_count_hex,
                uri,
                body,
            )?
        }
        Some(Algorithm::Sha256) => hash_common::<sha2::Sha256, Body>(
            method,
            chosen_qop,
            a1,
            nounce,
            cnounce,
            nounce_count_hex,
            uri,
            body,
        )?,
        Some(Algorithm::Sha256Sess) => {
            let a1_part1 =
                <sha2::Sha256>::digest(format!("{}:{}:{}", username, realm, password).as_bytes());
            let cnounce_ = cnounce.clone().ok_or(DigestError::MissingCNonce)?;
            let a1 = format!(
                "{}:{}",
                hex::encode(a1_part1),
                format!("{}:{}", nounce, cnounce_)
            );
            hash_common::<sha2::Sha256, Body>(
                method,
                chosen_qop,
                a1,
                nounce,
                cnounce,
                nounce_count_hex,
                uri,
                body,
            )?
        }
        Some(Algorithm::Other(s)) => {
            return Err(DigestError::DigestAlgorithmNotImplemented(
                Algorithm::Other(s),
            ))
        }
    };
    challenge_response.response = Some(response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::digest::*;
    #[test]
    //Tests example from OLD RFC
    fn rfc_md5_auth_old_rfc() {
        //env_logger::init();
        let username = "Mufasa".to_string();
        let userhash = Some(false);
        //Old RFC has `Of` instead of `of` as in the new RFC
        let password = "Circle Of Life".to_string();
        let realm = "testrealm@host.com".to_string();
        let qop = Qop::Auth;
        let uri = "/dir/index.html".to_string();
        let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string();
        let opaque = "5ccc069c403ebaf9f0171e9517f40e41".to_string();
        let nounce_count = 1;
        let cnounce = "0a4f113b".to_string();
        let expected_response = "6629fae49393a05397450978507c4ef1".to_string();
        let mut challenge_response = DigestChallengeResponse {
            username: username,
            realm: Some(realm),
            qop: Some(qop),
            algorithm: None,
            nounce: nonce.clone(),
            cnounce: Some(cnounce),
            nounce_count: Some(nounce_count),
            opaque: Some(opaque),
            uri: uri,
            stale: userhash,
            userhash: None,
            response: None,
        };
        digest_response(
            Some("GET".to_string()),
            password,
            &mut challenge_response,
            &Vec::<u8>::new(),
        )
        .unwrap();
        let response = challenge_response.response.clone().unwrap();
        assert_eq!(
            response,
            expected_response,
            "digest does not match expected one from RFC. digest: {}, expected:{}",
            response.clone(),
            expected_response
        );
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
    }

    #[test]
    //Tests example from https://tools.ietf.org/html/rfc7616#page-18
    //3d78807defe7de2157e2b0b6573a855f
    fn rfc_md5_auth() {
        //env_logger::init();
        let username = "Mufasa".to_string();
        let userhash = Some(false);
        let password = "Circle of Life".to_string();
        let realm = "http-auth@example.org".to_string();
        let qop = Qop::Auth;
        //let mut qops = Vec::<Qop>::new();
        //qops.push(qop);
        let uri = "/dir/index.html".to_string();
        let nonce = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_string();
        let opaque = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_string();
        let nounce_count = 1;
        let cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_string();
        let expected_response = "8ca523f5e9506fed4657c9700eebdbec".to_string();
        let mut challenge_response = DigestChallengeResponse {
            username: username,
            realm: Some(realm),
            qop: Some(qop),
            algorithm: Some(Algorithm::Md5),
            cnounce: Some(cnonce),
            nounce_count: Some(nounce_count),
            nounce: nonce.clone(),
            opaque: Some(opaque),
            uri: uri,
            stale: Some(false),
            userhash: userhash,
            response: None,
        };
        digest_response(
            Some("GET".to_string()),
            password,
            &mut challenge_response,
            &Vec::<u8>::new(),
        )
        .unwrap();
        let response = challenge_response.response.clone().unwrap();
        assert_eq!(
            response,
            expected_response,
            "digest does not match expected one from RFC. digest: {}, expected:{}",
            response.clone(),
            expected_response
        );
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
    }

    #[test]
    fn md5_example_from_real_camera() {
        //env_logger::init();
        let username = "admin".to_string();
        let userhash = Some(false);
        let password = "19929394".to_string();
        let realm = "RTSPD".to_string();
        let qop = None;
        //let mut qops = Vec::<Qop>::new();
        //qops.push(qop);
        let uri = "/tcp/av0_0".to_string();
        let nonce = "5t0mb2p1409hb58g863p73ay9wu6361y".to_string();
        let opaque = "".to_string();
        let nounce_count = 1;
        let cnonce = "".to_string();
        let expected_response = "a7a0164da8f17d1d453da956b1ce3119".to_string();
        let mut challenge_response = DigestChallengeResponse {
            username: username,
            realm: Some(realm),
            qop: qop,
            algorithm: Some(Algorithm::Md5),
            cnounce: Some(cnonce),
            nounce_count: Some(nounce_count),
            nounce: nonce.clone(),
            opaque: Some(opaque),
            uri: uri,
            stale: Some(false),
            userhash: userhash,
            response: None,
        };
        digest_response(
            Some("TEARDOWN".to_string()),
            password,
            &mut challenge_response,
            &Vec::<u8>::new(),
        )
        .unwrap();
        let response = challenge_response.response.clone().unwrap();
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
        assert_eq!(response, expected_response);
    }

    #[test]
    fn md5_example_from_real_camer_2() {
        //env_logger::init();
        let username = "admin".to_string();
        let userhash = Some(false);
        let password = "19929394".to_string();
        let realm = "RTSPD".to_string();
        let qop = None;
        //let mut qops = Vec::<Qop>::new();
        //qops.push(qop);
        let uri = "/tcp/av0_0".to_string();
        let nonce = "j50g9hf5ll9g5grqj3357r9n7kum9np4".to_string();
        let opaque = "".to_string();
        let nounce_count = 1;
        let cnonce = "".to_string();
        let expected_response = "efbac8cd3152ad98882a85995580fb9a".to_string();
        let mut challenge_response = DigestChallengeResponse {
            username: username,
            realm: Some(realm),
            qop: qop,
            algorithm: Some(Algorithm::Md5),
            cnounce: Some(cnonce),
            nounce_count: Some(nounce_count),
            nounce: nonce.clone(),
            opaque: Some(opaque),
            uri: uri,
            stale: Some(false),
            userhash: userhash,
            response: None,
        };
        digest_response(
            Some("DESCRIBE".to_string()),
            password,
            &mut challenge_response,
            &Vec::<u8>::new(),
        )
        .unwrap();
        let response = challenge_response.response.clone().unwrap();
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
        assert_eq!(response, expected_response);
    }

    #[test]
    //Tests example from https://tools.ietf.org/html/rfc7616#page-18
    fn rfc_sha256_auth() {
        //env_logger::init();
        let username = "Mufasa".to_string();
        let userhash = Some(false);
        let password = "Circle of Life".to_string();
        let realm = "http-auth@example.org".to_string();
        let qop = Qop::Auth;
        //let mut qops = Vec::<Qop>::new();
        //qops.push(qop);
        let uri = "/dir/index.html".to_string();
        let nonce = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_string();
        let opaque = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_string();
        let nounce_count = 1;
        let cnounce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ".to_string();
        let expected_response =
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1".to_string();
        let mut challenge_response = DigestChallengeResponse {
            username: username,
            realm: Some(realm),
            qop: Some(qop),
            algorithm: Some(Algorithm::Sha256),
            nounce: nonce.clone(),
            nounce_count: Some(nounce_count),
            cnounce: Some(cnounce),
            opaque: Some(opaque),
            uri: uri,
            stale: Some(false),
            userhash: userhash,
            response: None,
        };
        digest_response(
            Some("GET".to_string()),
            password,
            &mut challenge_response,
            &Vec::<u8>::new(),
        )
        .unwrap();
        let response = challenge_response.response.clone().unwrap();
        assert_eq!(
            response,
            expected_response,
            "digest does not match expected one from RFC. digest: {}, expected:{}",
            response.clone(),
            expected_response
        );
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
    }

    //TODO: does RTSP 1.0 support custom charset?
    /*
    #[test]
    //Tests example from https://tools.ietf.org/html/rfc7616#page-18
    fn rfc_sha512_265_with_charset_and_userhash() {
        //env_logger::init();
        let username = "Jäsøn Doe".to_string();
        let password = "Secret, or not".to_string();
        let realm = "api@example.org".to_string();
        let qop = Qop::Auth;
        //let mut qops = Vec::<Qop>::new();
        //qops.push(qop);
        let uri = "/doe.json".to_string();
        let nonce="5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK".to_string();
        let opaque="HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS".to_string();
        let nounce_count = 1;
        let cnounce = "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v".to_string();
        let expected_response = "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd".to_string();
        let mut challenge_response = DigestChallengeResponse{
            username: username,
            realm: Some(realm),
            qop: Some(qop),
            algorithm: Some(Algorithm::Sha256),
            nounce: nonce.clone(),
            cnounce: cnounce,
            nounce_count: nounce_count,
            opaque: Some(opaque),
            uri: uri,
            stale: Some(false),
            userhash: None,
            response: None
        };
        digest_response(Some("GET".to_string()), password, &mut challenge_response, None).unwrap();
        let response = challenge_response.response.clone().unwrap();
        assert_eq!(response, expected_response, "digest does not match expected one from RFC. digest: {}, expected:{}", response.clone(), expected_response);
        let mut buffer = Vec::<u8>::new();
        challenge_response.serialize(&mut buffer).unwrap();
        println!("{}", String::from_utf8_lossy(buffer.as_slice()));
    }
    */
}
