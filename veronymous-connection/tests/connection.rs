use crypto_common::rand_non_zero_fr;
use rand::thread_rng;
use veronymous_connection::model::ConnectRequest;
use veronymous_token::issuer::TokenIssuer;
use veronymous_token::root_exchange::{
    complete_root_token, create_root_token_request, issue_root_token,
};

#[test]
fn test_connection_request() {
    // 1) Issue the token
    let mut rng = thread_rng();

    // Create a token issuer
    let issuer = TokenIssuer::generate(&mut rng);

    let token_id = rand_non_zero_fr(&mut rng);
    let blinding = rand_non_zero_fr(&mut rng);

    // Create token request
    let token_request =
        create_root_token_request(&token_id, &blinding, &issuer.public_key, &issuer.params)
            .unwrap();

    // Sign the token
    let token_response = issue_root_token(
        &token_request,
        &issuer.signing_key,
        &issuer.public_key,
        &issuer.params,
        &mut rng,
    )
        .unwrap();

    // Complete the token
    let root_token = complete_root_token(
        &token_response,
        &token_id,
        &blinding,
        &issuer.public_key,
        &issuer.params,
    )
        .unwrap();

    // 2) Create the token
    let domain = "test".as_bytes();
    let epoch = 1643629600u64;

    let veronymous_token = root_token
        .derive_token(domain, epoch, &issuer.public_key, &issuer.params, &mut rng)
        .unwrap();

    // 3) Create the connection request
    let public_key = [
        148, 59, 217, 215, 192, 60, 91, 222, 49, 113, 226, 92, 207, 79, 18, 57, 42, 23, 23, 8, 64,
        149, 105, 64, 85, 86, 121, 15, 13, 212, 3, 65,
    ];

    let connect_request = ConnectRequest::new(public_key, veronymous_token);

    // Verify
    let result = connect_request.verify(domain, epoch, &issuer.public_key, &issuer.params).unwrap();
    assert!(result);

    // Verification should fail for another epoch
    let epoch = 1643629700u64;
    let result = connect_request.verify(domain, epoch, &issuer.public_key, &issuer.params).unwrap();
    assert_eq!(false, result);
}