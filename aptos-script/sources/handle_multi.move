script {
    fun main(owner_signer: &signer, public_key: vector<u8>) {
        0x7f07ca4fd4b1bc28a6d18348158ca39af540c9d3c703940a5843c5c4b126ebc4::SupraSValueFeed::update_public_key(owner_signer, public_key);
    }
}
module 0x7f07ca4fd4b1bc28a6d18348158ca39af540c9d3c703940a5843c5c4b126ebc4::SupraSValueFeed {
    native public fun update_public_key(owner_signer: &signer, public_key: vector<u8>);
}
