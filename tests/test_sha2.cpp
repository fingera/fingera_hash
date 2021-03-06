#include <fingera/hash/sha2.h>

#include <gtest/gtest.h>

#include "test_utility.h"

TEST(sha2_256, normal) {
  // bitcoin
  test_sha256(
      "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  test_sha256(
      "abc",
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  test_sha256(
      "message digest",
      "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
  test_sha256(
      "secure hash algorithm",
      "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
  test_sha256(
      "SHA256 is considered to be safe",
      "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
  test_sha256(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  test_sha256(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnop",
      "aa353e009edbaebfc6e494c8d847696896cb8b398e0173a4b5c1b636292d87c7");
  test_sha256(
      "For this sample, this 63-byte string will be used as input data",
      "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
  test_sha256(
      "This is exactly 64 bytes long, not counting the terminating byte",
      "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
  test_sha256(
      "As Bitcoin relies on 80 byte header hashes, we want to have an example "
      "for that.",
      "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
  test_sha256(
      std::string(1000000, 'a').c_str(),
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(sha2_512, normal) {
  // bitcoin
  test_sha512(
      "",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  test_sha512(
      "abc",
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  test_sha512(
      "message digest",
      "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
      "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
  test_sha512(
      "secure hash algorithm",
      "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3"
      "d5db502e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e");
  test_sha512(
      "SHA512 is considered to be safe",
      "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a9964"
      "6b4a3901caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2");
  test_sha512(
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
      "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
  test_sha512(
      "For this sample, this 63-byte string will be used as input data",
      "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e"
      "6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766");
  test_sha512(
      "This is exactly 64 bytes long, not counting the terminating byte",
      "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38"
      "7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030");
  test_sha512(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
      "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
      "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
  test_sha512(
      std::string(1000000, 'a').c_str(),
      "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
      "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
}

TEST(sha256_hmac, normal) {
  test_hmac_sha256(
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
  test_hmac_sha256(
      "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
  test_hmac_sha256(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddd",
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
  test_hmac_sha256(
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
  test_hmac_sha256(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
      "65204b6579202d2048617368204b6579204669727374",
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
  test_hmac_sha256(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468"
      "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
      "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
      "647320746f20626520686173686564206265666f7265206265696e6720757365"
      "642062792074686520484d414320616c676f726974686d2e",
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
  // Test case with key length 63 bytes.
  test_hmac_sha256(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "9de4b546756c83516720a4ad7fe7bdbeac4298c6fdd82b15f895a6d10b0769a6");
  // Test case with key length 64 bytes.
  test_hmac_sha256(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "528c609a4c9254c274585334946b7c2661bad8f1fc406b20f6892478d19163dd");
  // Test case with key length 65 bytes.
  test_hmac_sha256(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "d06af337f359a2330deffb8e3cbe4b5b7aa8ca1f208528cdbd245d5dc63c4483");
}

TEST(sha512_hmac, normal) {
  test_hmac_sha512(
      "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
      "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
  test_hmac_sha512(
      "4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
      "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
  test_hmac_sha512(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddd",
      "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
      "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
  test_hmac_sha512(
      "0102030405060708090a0b0c0d0e0f10111213141516171819",
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
      "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
  test_hmac_sha512(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",
      "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
      "65204b6579202d2048617368204b6579204669727374",
      "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
      "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");
  test_hmac_sha512(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaa",
      "5468697320697320612074657374207573696e672061206c6172676572207468"
      "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
      "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
      "647320746f20626520686173686564206265666f7265206265696e6720757365"
      "642062792074686520484d414320616c676f726974686d2e",
      "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
      "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58");
  // Test case with key length 127 bytes.
  test_hmac_sha512(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a6566",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "267424dfb8eeb999f3e5ec39a4fe9fd14c923e6187e0897063e5c9e02b2e624a"
      "c04413e762977df71a9fb5d562b37f89dfdfb930fce2ed1fa783bbc2a203d80e");
  // Test case with key length 128 bytes.
  test_hmac_sha512(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "43aaac07bb1dd97c82c04df921f83b16a68d76815cd1a30d3455ad43a3d80484"
      "2bb35462be42cc2e4b5902de4d204c1c66d93b47d1383e3e13a3788687d61258");
  // Test case with key length 129 bytes.
  test_hmac_sha512(
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a6566654a6566654a6566654a6566654a6566654a6566654a6566654a656665"
      "4a",
      "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      "0b273325191cfc1b4b71d5075c8fcad67696309d292b1dad2cd23983a35feb8e"
      "fb29795e79f2ef27f68cb1e16d76178c307a67beaad9456fac5fdffeadb16e2c");
}
