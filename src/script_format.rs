pub const SCRIPT: &str = r#"script {
    fun main(owner_signer: &signer, public_key: vector<u8>) {
        $address::$module::$function(owner_signer, public_key);
    }
}
module $address::$module {
    native public fun $function(owner_signer: &signer, public_key: vector<u8>);
}"#;
