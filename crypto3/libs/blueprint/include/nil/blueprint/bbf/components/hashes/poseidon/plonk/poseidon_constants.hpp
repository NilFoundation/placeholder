//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BBF_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP
#define CRYPTO3_BBF_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP

#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>
#include <nil/crypto3/algebra/matrix/matrix.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {
            namespace components {
                namespace detail {

                    template<typename ConstFieldType>
                    struct poseidon_constants;

                    template<>
                    struct poseidon_constants<
                        typename nil::crypto3::algebra::fields::pallas_base_field> {
                        using FieldType = nil::crypto3::algebra::fields::pallas_base_field;
                        constexpr static const std::size_t state_size = 3;
                        constexpr static const std::size_t full_rounds_amount = 55;
                        constexpr static const std::size_t partial_rounds_amount = 0;
                        constexpr static const std::size_t total_rounds_amount =
                            full_rounds_amount + partial_rounds_amount;
                        constexpr static const std::size_t sbox_alpha = 7;
                        constexpr static bool pasta_version = true;

                        constexpr static const std::array<
                            std::array<typename FieldType::value_type, state_size>, state_size>
                            mds = {{
                                {{0x1a9bd250757e29ef4959b9bef59b4e60e20a56307d6491e7b7ea1fac679c7903_big_uint255,
                                  0x384aa09faf3a48737e2d64f6a030aa242e6d5d455ae4a13696b48a7320c506cd_big_uint255,
                                  0x3d2b7b0209bc3080064d5ce4a7a03653f8346506bfa6d076061217be9e6cfed5_big_uint255}},
                                {{0x9ee57c70bc351220b107983afcfabbea79868a4a8a5913e24b7aaf3b4bf3a42_big_uint255,
                                  0x20989996bc29a96d17684d3ad4c859813115267f35225d7e1e9a5b5436a2458f_big_uint255,
                                  0x14e39adb2e171ae232116419ee7f26d9191edde8a5632298347cdb74c3b2e69d_big_uint255}},
                                {{0x174544357b687f65a9590c1df621818b5452d5d441597a94357f112316ef67cb_big_uint255,
                                  0x3ca9263dc1a19d17cfbf15b0166bb25f95dffc53212db207fcee35f02c2c4137_big_uint255,
                                  0x3cf1fbef75d4ab63b7a812f80b7b0373b2dc21d269ba7c4c4d6581d50aae114c_big_uint255}},
                            }};

                        constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, total_rounds_amount> round_constant = {{
                            {{0x2ec559cd1a1f2f6889fc8ae5f07757f202b364429677c8ff6603fd6d93659b47_big_uint255,
                              0x2553b08c788551bfe064d91c17eb1edb8662283229757711b2b30895f0aa3bad_big_uint255,
                              0x25a706fb0f35b260b6f28d61e082d36a8f161be1f4d9416371a7b65f2bfafe4e_big_uint255}},
                            {{0x37c0281fda664cc2448d0e7dd77aaa04752250817a945abeea8cfaaf3ee39ba0_big_uint255,
                              0x140488321291998b8582eaceeb3fa9ca3980eb64a453573c5aaa2910405936b6_big_uint255,
                              0x3a73fe35b1bdd66b809aad5eab47b5c83b0146fd7fc632dfb49cd91ae1169378_big_uint255}},
                            {{0x21b7c2b35fd7710b06245711f26c0635d3e21de4db10dd3a7369f59f468d7be6_big_uint255,
                              0x1803a068d25fef2ef652c8a4847aa18a29d1885e7bf77fd6a34d66536d09cad7_big_uint255,
                              0x291de61c5e6268213772cf7e03c80c2e833eb77c58c46548d158a70fbbd9724b_big_uint255}},
                            {{0x230043a0dc2dfab63607cbe1b9c482fdd937fdefecc6905aa5012e89babead13_big_uint255,
                              0x218af77a05c502d3fa3144efcf47a0f2a0292498c10c6e2368565674e78764f4_big_uint255,
                              0x223e2d94c177d27e071d55729d13a9b216955c7102cc9a95ea40058efb506117_big_uint255}},
                            {{0x2a18257c15ad9b6fe8b7c5ad2129394e902c3c3802e738f24ce2f585ae5f6a38_big_uint255,
                              0xa6f7ba75f216403d2e4940469d199474a65aa5ef814e36400bddef06158dcf8_big_uint255,
                              0x169be41c6227956efef5b4cdde65d00d5e04fe766178bdc731615c6e5b93e31e_big_uint255}},
                            {{0x2e28f50a9a55d2e91774083072734544417e290a1cfebc01801b94d0728fe663_big_uint255,
                              0xfdedf8da8654a22831040cfc74432464b173ee68628fd90498480b9902f2819_big_uint255,
                              0x46a3ed9863d2d739dd8bc9e90a746fda1197162d0a0bec3db1f2f6042cf04e2_big_uint255}},
                            {{0x219e08b460c305b428670bacab86ac1e9458075778d35c3619ae7ba1f9b2ed76_big_uint255,
                              0x38bb36a12ebcec4d4e8728eb43e3f12a6e33b1ffa1463379018d4e12424e62ca_big_uint255,
                              0x1e9aa3fe25d116ccfbd6a8fccdae0aa9bc164a03ab7e951704ee9a715fbedee6_big_uint255}},
                            {{0x30f33ed70da4c2bfb844ff1a7558b817d1ec300da86a1694f2db45047d5f18b_big_uint255,
                              0x282b04137350495ab417cf2c47389bf681c39f6c22d9e370b7af75cbcbe4bb1_big_uint255,
                              0x9b1528dea2eb5bd96905b88ff05fdf3e0f220fe1d93d1b54953ac98fec825f0_big_uint255}},
                            {{0x30083dbbb5eab39311c7a8bfd5e55567fa864b3468b5f9200e529cda03d9ef71_big_uint255,
                              0x17eace73cf67c6112239cbf51dec0e714ee4e5a91dbc9209dc17bbea5bcd094_big_uint255,
                              0x37af1de8f5475ba165b90f8d568683d54e215df97e9287943370cf4118428097_big_uint255}},
                            {{0x16ff7592836a45340ec6f2b0f122736d03f0bcb84012f922a4baa73ea0e66f51_big_uint255,
                              0x1a5985d4b359d03de60b2edabb1853f476915febc0e40f83a2d1d0084efc3fd9_big_uint255,
                              0x255a9d4beb9b5ea18ab9782b1abb267fc5b773b98ab655fd4d469698e1e1f975_big_uint255}},
                            {{0x34a8d9f45200a9ac28021712be81e905967bac580a0b9ee57bc4231f5ecb936a_big_uint255,
                              0x979556cb3edcbe4f33edd2094f1443b4b4ec6c457b0425b8463e788b9a2dcda_big_uint255,
                              0x2a4d028c09ad39c30666b78b45cfadd5279f6239379c689a727f626679272654_big_uint255}},
                            {{0xc31b68f6850b3bd71fe4e89984e2c87415523fb54f24ec8ae71430370154b33_big_uint255,
                              0x1a27ca0b953d3dba6b8e01cf07d76c611a211d139f2dff5ac023ed2454f2ed90_big_uint255,
                              0x109ae97c25d60242b86d7169196d2212f268b952dfd95a3937916b9905303180_big_uint255}},
                            {{0x3698c932f2a16f7bb9abac089ec2de79c9965881708878683caf53caa83ad9c4_big_uint255,
                              0x3c7e25e0ac8fba3dc1360f8a9a9fa0be0e031c8c76a93497b7cac7ed32ade6c0_big_uint255,
                              0x2fc5023c5e4aed5aa7dfca0f5492f1b6efab3099360ec960237512f48c858a79_big_uint255}},
                            {{0x2c124735f3f924546fb4fdfa2a018e03f53063d3a2e87fd285ba8d647eda6765_big_uint255,
                              0x12c875c9b79591acf9033f8b6c1e357126c44b23f3486fbee0d98340a3382251_big_uint255,
                              0x3cda935e895857d39a7db8476aeda5a5131cb165a353073fd3e473fd8855528d_big_uint255}},
                            {{0x218eb756fa5f1df9f1eb922ef80b0852588779a7368e3d010def1512815d8759_big_uint255,
                              0x23bcf1032957015ef171fbb4329bca0c57d59885522f25f4b082a3cf301cfbc6_big_uint255,
                              0x17474c3b6a9bc1057df64b9e4d62badbc7f3867b3dd757c71c1f656205d7bceb_big_uint255}},
                            {{0x19826c0ee22972deb41745d3bd412c2ae3d4c18535f4b60c9e870edffa3d550_big_uint255,
                              0x30bcb17dfd622c46f3275f698319b68d8816bed0368ded435ed61992bc43efa9_big_uint255,
                              0x3bd816c214c66410229cfbd1f4a3a42e6a0f82f3c0d49b09bc7b4c042ff2c94b_big_uint255}},
                            {{0x8943ec01d9fb9f43c840757738979b146c3b6d1982280e92a52e8d045633ea1_big_uint255,
                              0x2670bf8c01822e31c70976269d89ed58bc79ad2f9d1e3145df890bf898b57e47_big_uint255,
                              0xdd53b41599ae78dbd3e689b65ebcca493effa94ed765eeec75a0d3bb20407f9_big_uint255}},
                            {{0x68177d293585e0b8c8e76a8a565c8689a1d88e6a9afa79220bb0a2253f203c3_big_uint255,
                              0x35216f471043866edc324ad8d8cf0cc792fe7a10bf874b1eeac67b451d6b2cf5_big_uint255,
                              0x1fd6efb2536bfe11ec3736e7f7448c01eb2a5a9041bbf84631cc83ee0464f6af_big_uint255}},
                            {{0x2c982c7352102289fc1b48dafcd9e3cc364d5a4324575e4721daf0af10033c67_big_uint255,
                              0x352f7e8c7662d86db9c722d4d07778858771b832af5bb5dc3b13cf94851c1b45_big_uint255,
                              0x18e3c0c1caa5e3ed66ee1ab6f55a5c8063d8c9b034ae47db43435147149e37d5_big_uint255}},
                            {{0x3124b12deb37dcbb3d96c1a08d507523e30e03e0919559bf2daaab238422eade_big_uint255,
                              0x143bf0def31437eb21095200d2d406e6e5727833683d9740b9bfc1713215dc9a_big_uint255,
                              0x1ebee92143f32b4f9d9a90ad62b8483c977480767b53c71f6bde934a8ef38f17_big_uint255}},
                            {{0xff6c794ad1afaa494088d5f8ee6c47bf9e83013478628cf9f41f2e81383ebeb_big_uint255,
                              0x3d0a10ac3ee707c62e8bdf2cdb49ac2cf4096cf41a7f214fdd1f8f9a24804f17_big_uint255,
                              0x1d61014cd3ef0d87d037c56bdfa370a73352b95d472ead1937bed06a31801c91_big_uint255}},
                            {{0x123e185b2ec7f072507ac1e4e743589bb25c8fdb468e329e7de169875f90c525_big_uint255,
                              0x30b780c0c1cb0609623732824c75017da9799bdc7e08b527bae7f409ebdbecf2_big_uint255,
                              0x1dfb3801b7ae4e209f68195612965c6e37a2ed5cf1eeee3d46edf655d6f5afef_big_uint255}},
                            {{0x2fdee42805b2774064e963c741552556019a9611928dda728b78311e1f049528_big_uint255,
                              0x31b2b65c431212ed36fdda5358d90cd9cb51c9f493bff71cdc75654547e4a22b_big_uint255,
                              0x1e3ca033d8413b688db7a543e62ac2e69644c0614801379cfe62fa220319e0ef_big_uint255}},
                            {{0xc8ef1168425028c52a32d93f9313153e52e9cf15e5ec2b4ca09d01730dad432_big_uint255,
                              0x378c73373a36a5ed94a34f75e5de7a7a6187ea301380ecfb6f1a22cf8552638e_big_uint255,
                              0x3218aeec20048a564015e8f221657fbe489ba404d7f5f15b829c7a75a85c2f44_big_uint255}},
                            {{0x3312ef7cbbad31430f20f30931b070379c77119c1825c6560cd2c82cf767794e_big_uint255,
                              0x356449a71383674c607fa31ded8c0c0d2d20fb45c36698d258cecd982dba478c_big_uint255,
                              0xcc88d1c91481d5321174e55b49b2485682c87fac2adb332167a20bcb57db359_big_uint255}},
                            {{0x1defccbd33740803ad284bc48ab959f349b94e18d773c6c0c58a4b9390cc300f_big_uint255,
                              0x2d263cc2e9af126d768d9e1d2bf2cbf32063be831cb1548ffd716bc3ee7034fe_big_uint255,
                              0x111e314db6fb1a28e241028ce3d347c52558a33b6b11285a97fffa1b479e969d_big_uint255}},
                            {{0x27409401e92001d434cba2868e9e371703199c2372d23ef329e537b513f453e_big_uint255,
                              0x24a852bdf9cb2a8fedd5e85a59867d4916b8a57bdd5f84e1047d410770ffffa0_big_uint255,
                              0x205d1b0ee359f621845ac64ff7e383a3eb81e03d2a2966557746d21b47329d6e_big_uint255}},
                            {{0x25c327e2cc93ec6f0f23b5e41c931bfbbe4c12da7d55a2b1c91c79db982df903_big_uint255,
                              0x39df3e22d22b09b4265da50ef175909ce79e8f0b9599dff01cf80e70884982b9_big_uint255,
                              0x9b08d58853d8ac908c5b14e5eb8611b45f40faaa59cb8dff98fb30efcdfaa01_big_uint255}},
                            {{0x1ece62374d79e717db4a68f9cddaaf52f8884f397375c0f3c5c1dbaa9c57a0a6_big_uint255,
                              0x3bd089b727a0ee08e263fa5e35b618db87d7bcce03441475e3fd49639b9fa1c1_big_uint255,
                              0x3fedea75f37ad9cfc94c95141bfb4719ee9b32b874b93dcfc0cc12f51a7b2aff_big_uint255}},
                            {{0x36dfa18a9ba1b194228494a8acaf0668cb43aca9d4e0a251b20ec3424d0e65cd_big_uint255,
                              0x119e98db3f49cd7fcb3b0632567d9ccaa5498b0d411a1437f57c658f41931d0c_big_uint255,
                              0x1100b21c306475d816b3efcd75c3ae135c54ad3cc56ca22abd9b7f45e6d02c19_big_uint255}},
                            {{0x15791f9bbea213937208c82794eb667f157f003c65b64aa9800f4bbee4ea5119_big_uint255,
                              0x1adbeb5e9c4d515ecfd250ebee56a2a816eb3e3dc8d5d440c1ab4285b350be64_big_uint255,
                              0x1fbf4738844a9a249aec253e8e4260e4ab09e26bea29ab0020bf0e813ceecbc3_big_uint255}},
                            {{0x3418a929556ec51a086459bb9e63a821d407388cce83949b9af3e3b0434eaf0e_big_uint255,
                              0x9406b5c3af0290f997405d0c51be69544afb240d48eeab1736cda0432e8ff9e_big_uint255,
                              0x23ece5d70b38ccc9d43cd923e5e3e2f62d1d873c9141ef01f89b6de1336f5bc7_big_uint255}},
                            {{0x1852d574e46d370a0b1e64f6c41eeb8d40cf96c524a62965661f2ef87e67234d_big_uint255,
                              0xa657027cce8d4f238ea896dde273b7537b508674a366c66b3789d9828b0ce90_big_uint255,
                              0x3482f98a46ec358108fbbb68fd94f8f2baa73c723baf21922a850e45511f5a2d_big_uint255}},
                            {{0x3f62f164f8c905b335a6cbf76131d2430237e17ad6abc76d2a6329c1ec5463ee_big_uint255,
                              0x7e397f503f9c1cea028465b2950ea444b15c5eab567d5a69ea2925685694df0_big_uint255,
                              0x405f1fc711872373d6eb50a09fbfb05b2703ae0a0b4edb86aedb216db17a876_big_uint255}},
                            {{0xbe0848eb3e09c7027110ad842c502441c97afa14a844406fcfec754a25658c1_big_uint255,
                              0x26b78788fd98ac020bac92d0e7792bb5ffed06b697d847f61d984f905d9ba870_big_uint255,
                              0x38fd5318d39055c82fef9bdd33315a541c0ec4363e6cc0687005871355dfa573_big_uint255}},
                            {{0x380bd03b840c48c8ba3830e7cace72f91a5002218c617294e8c8bc687d5216de_big_uint255, 0x2c6e57ddc1d7c81a0299ed49c3d74759416bc8426f30e2af5622895c531b4e1c_big_uint255,
                              0x11d3a81b262fc76ef506ee6d88e5991d0de8cb9dd162d97c58b175e3bc4584f3_big_uint255}},
                            {{0x9b6b283ebaf45fbb1e448969ace9be62adf67ddf58614925741deb6a1ba7def_big_uint255,
                              0x15d5095164c885763fa83cdf776d436382821a17bc5563a5b6f6dfcdac504ade_big_uint255,
                              0x3427fdbfca3cea23063eb138c5055c6cad9c4252b23d12c12293308eff7d9124_big_uint255}},
                            {{0x272f12e731077b74317ef2543c33b86194db1da5f6a7e1eee0656672c81685fe_big_uint255,
                              0x5323f85deb8c07c193c37a73d76f6114967913a2bdce11995f183e769f42967_big_uint255,
                              0x3d5ce415ecae4ba42b417ea3a501b44694f46efddff2fcca952b097f3852d3d8_big_uint255}},
                            {{0xe8ec18c7b52c514d42047f1f0b2a90cb8c0c7391cf9479cd7fd5bfe1d3db8f2_big_uint255,
                              0x1591c865ea7065d54304519f8bb268bddbeaf3afae54edcd01a833ed0a9ef1a_big_uint255,
                              0x3eddbeeee5eca5deee4bf1789c435e1241e0d71186d8f0f62d74729dfc3119fb_big_uint255}},
                            {{0x23691c7009b9283b268766e8d491716d3c1993e6ecf458def8f762af3e355707_big_uint255,
                              0x26cdab2c837ebeac5bea4be1d6f0488034907374d81a61a34f1c4db397d4c09b_big_uint255,
                              0x2d2206730664d58be0676dad1fee0e990c264a7410a2cdb6b55653c1df72ef56_big_uint255}},
                            {{0x2bb74bb185372334a4ef5f6d18e2ece54086e62b04985dd794b7117b0be9217f_big_uint255,
                              0x366250fe928c45d8d5aa35f0a142754907ff3c598410199b589b28cd851b2204_big_uint255,
                              0x1868f8118482c6b4a5a61a81c8aaca128953179c20f73a44022d9976bdc34af1_big_uint255}},
                            {{0xb7901c670e1d75d726eb88d000950b3c963f0f7a6ca24994bdc07ae2f78b4d3_big_uint255,
                              0x32c4bd8ab70e1f25af77af57dd340c8e6c8a101dfc5e8dd03314566db90b870_big_uint255,
                              0x1ce36db31fe6ea3cd9308db9aa43a8af5c41a8f0a6509bfe00f0e7b486c0ab8a_big_uint255}},
                            {{0x26596ea9e1915e53da3479e9d13c3c920505e2449e325810ff6ca855fe4b7c6e_big_uint255,
                              0x30f296a269868a7fca8f5b1e269c0116304df31729559a270e713509d3a6d5dc_big_uint255,
                              0x2588961eff7897d87eb6ac72350ef9f52640647cbd23136919a994dfd1979d5_big_uint255}},
                            {{0x16a49e69721e80690d41e06229e9bc2dbaf9a2abf4b89388db2485595409d62b_big_uint255,
                              0x3d7aca02c051fcad8073cfd67210cd423a31888afc4a444d9d3adf3d6c5da7bf_big_uint255,
                              0x299bd48a740b7790075268312ab8072c72421de5a6437fa5e25431ef951847b4_big_uint255}},
                            {{0x11a69b867d9ea22ec1b2f28e96617129e36eefaea9e8126bdc6a42b99072902b_big_uint255,
                              0x25bc1af391f3c1f2284a95da92b5883d1b3a40794b2358b2e7a70fca22da64ce_big_uint255,
                              0x361ab3843f4d8ddadede39d82bb1a8109f89b6d9aa117b8f365de43895de0baa_big_uint255}},
                            {{0x38ef3ab5b61c117a3465a017a9c8ba4c227659b41fdf145206d5c960f49dd45b_big_uint255,
                              0x3992f83f26143dbdbd335604a1a14daf238ae43c249783f694feaf560aaae20f_big_uint255,
                              0x350287977eb71c81b10ecd039aad99cfa9ed84a04301cb30869e1dc7fa1dc638_big_uint255}},
                            {{0x3afb5bc126020586dcccba32dd054cd9a3f3b834ca9678d6802c48b1da97d6ed_big_uint255,
                              0x172b7c2d8e7e4b06d183a2575b790749d0970c54966407fa8f59072c729de671_big_uint255,
                              0x2eb53fe3a278688a70494569e54a0f0d269935aec6c897bef4d368c1f67d57e4_big_uint255}},
                            {{0x375ae56b8d9310d553ed77d406dedc3f0393e5a321b71caee6a5bb7078b5035_big_uint255,
                              0x1d49a0d53bc2993cbf1fb5d1da9bb76fe46a7031d5e5d43fadbf54bc17c1ef38_big_uint255,
                              0x132d17b87cab6d707ddfa1f01df1724ad37957e989c44f1ff71426367f953160_big_uint255}},
                            {{0x62da5280948d8c6c4acc7e6a1aa421f0f9ec179a44146750060be4be6755f85_big_uint255,
                              0xa4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_big_uint255,
                              0x3356f1fbeac493ccab752b70bbed821ce49965c19284d7aacd78fbf3ff864e91_big_uint255}},
                            {{0x42721e8a9cc32557851feb0e0190c5dfbf4cb1b8f47d37e7e653ec6ff8a4059_big_uint255,
                              0x53d9b2633fff31ca4fc5724ce6b4422318128cdf01897d321e86f47cdf748b1_big_uint255,
                              0x267d96caeafde5dbd3db1f0668b09ccd532a22f0205494716a786219fb4c801c_big_uint255}},
                            {{0x39316997737610193c3f9ffcfd4e23d38aac12cd7b95b8d256d774101650a6ca_big_uint255,
                              0x191e377462986563fdabf9b23529f7c84c6b200b9101b3a5096bca5f377981fb_big_uint255,
                              0x20f89af9722f79c860d2059a0ec209cf3a7925ad0798cab655eca62fe73ff3d9_big_uint255}},
                            {{0x1ca568aeddb2ef391a7c78ecf104d32d785b9ca145d97e35879df3534a7d1e0b_big_uint255,
                              0x25de9ba0a37472c3b4c0b9c3bc25cbbf78d91881b6f94ee70e4abf090211251c_big_uint255,
                              0x3393debd38d311881c7583bee07e605ef0e55c62f0508ccc2d26518cd568e1ef_big_uint255}},
                            {{0x38df2fd18a8d7563806aa9d994a611f642d5c397388d1dd3e78bc7a4515c5b1_big_uint255,
                              0x5c6503ff1ee548f2435ad9148d7fb94c9222b0908f445537a6667047f6d501c_big_uint255,
                              0x104c88d6d0682d82d3d664826dc9565db101a220aa8f90572eb798468a82a2ab_big_uint255}},
                            {{0x2caad6108c09ee6aee7851b4a2d2d3b7c3ca3c56a80003c8471f90bfa4ac628b_big_uint255,
                              0xa57dbd4c327826c8a97bc7285f94bcddb966177346f1792c4bd7088aa0353f3_big_uint255,
                              0x3c15552f9124318b8433d01bb53ba04ba1cc9eb91d83b918e32fea39fbe908fa_big_uint255}},
                            {{0xe10c10cbbe1717a9441c6299c4fc087c222208bd4fa8f3be66d2075f623b513_big_uint255,
                              0x1e8b254cbff2c92a83dff1728c81dd22a9570f590e497cb2d640042cb879a930_big_uint255,
                              0x1812dbcd70c440610057bbfdd0cc4d31d1faf5786419b53841c4adc43f2b2352_big_uint255}},
                        }};
                    };

                    template<>
                    struct poseidon_constants<
                        typename nil::crypto3::algebra::fields::vesta_base_field> {
                        using FieldType = nil::crypto3::algebra::fields::vesta_base_field;
                        constexpr static const std::size_t state_size = 3;
                        constexpr static const std::size_t full_rounds_amount = 55;
                        constexpr static const std::size_t partial_rounds_amount = 0;
                        constexpr static const std::size_t total_rounds_amount =
                            full_rounds_amount + partial_rounds_amount;
                        constexpr static const std::size_t sbox_alpha = 7;
                        constexpr static bool pasta_version = true;

                        constexpr static const std::array<
                            std::array<typename FieldType::value_type, state_size>, state_size>
                            mds = {{
                                {{
                                    0x3e28f7dd17f47a7e304a54d377dd7aeead6b92027d60baf300246cf023dd594e_big_uint255,
                                    0x30db06abb696fccb92b28ac214f4893d3fd84b3d4a9018754975e24477c32600_big_uint255,
                                    0x174110bc1b058c6016ff5e8152ab3ffb6e2e6c4d01e66aba302659c51b7f563a_big_uint255,
                                }},
                                {{
                                    0x12d36fa83503146980c05a1d48bcd50d2e9d4390e353a158a0fe387e2b4aeb0c_big_uint255,
                                    0x2ab17c8eb369bea76e9f0c385e8bafc71536bedc8e06d06fd65c1670e94d9c55_big_uint255,
                                    0xcc915328165c13986af127e108b9e5d9a60c5dc92e3e7636b8c3da5b4a8537_big_uint255,
                                }},
                                {{
                                    0x4d9a6d270696688eb4346153b380c613a3dcaf0fb5a1e8380409ae0a143d31b_big_uint255,
                                    0x2a805eee3317c8bae1f7d15abe4d27fee5fabcf9a3334d18b1932a33774c324_big_uint255,
                                    0x19b092e9c6dffd1eb1b6df2dbc00bb2283b9a787273dcbad9b8d89cd502b7bbd_big_uint255,
                                }},
                            }};

                        constexpr static const std::array<
                            std::array<typename FieldType::value_type, state_size>,
                            total_rounds_amount>
                            round_constant = {
                                {
                                    {{
                                        0x590ef2a14ba3cef7e8f93a6dde4d481057d5d0547f6f09341b6b8be19c00ee6_big_uint255,
                                        0x77faa77ed78ff8b695859df34db5157f6b491567f5f382a8fce538f0e5ffe6f_big_uint255,
                                        0x3e54b7c94955c8994ed16ec9950d59aca4c9b6e419ef4935682528c2eba2de50_big_uint255,
                                    }},
                                    {{
                                        0x37d991dc8d4de3912355745c7d78f8b04516b14d30e29324bb5dd075ca0f0c1d_big_uint255,
                                        0xc0614dd1cff6c6817aff09d82ef828e80caed4da023823088fd021020f81f0e_big_uint255,
                                        0x3335e335a3fed44842359528b3e88e1824a173da819d7ee6905e82eed054243_big_uint255,
                                    }},
                                    {{
                                        0xb2202aa54d42f4f07693766723b9624c9fca4d33a2b9ee40f1c809a15a48a1d_big_uint255,
                                        0x290253e0e1d2c72b32a5b272137a0892b5934b0b8f26b4fc25ea00d63a70e9df_big_uint255,
                                        0x3e99873e73025d7c8b71fd209d13dba7a1021013f0815ea33a42ae94b63d00f3_big_uint255,
                                    }},
                                    {{
                                        0x164682f55ec314f639f5f8062a4ddf11ed80d5822591a22ff54f340d90165d85_big_uint255,
                                        0x309ba21093c9d04c81bd5273ad1064e1bd9067312d3269dddadf74c2eb1d3e01_big_uint255,
                                        0x159e72bb030cb8994b2eac1d4ee7d0f06b0b092e7611d460605b3d8c60a274d9_big_uint255,
                                    }},
                                    {{
                                        0xd743dbfc6f3c833ce2ef4956bead3c118fd3198652038781903ac929218fdd6_big_uint255,
                                        0x18cb5a9230eb74045ede834ac6dd129bd2a0462dca1d96d167b9be0e1e96a688_big_uint255,
                                        0x2d82f85fc222b215902d61c85c968b39759d6c2e9aa0e11fd08881bfae311e66_big_uint255,
                                    }},
                                    {{
                                        0x2920828be5972cb8ff8023386a90a837bbfcca99be240137f7d211ecb72521e6_big_uint255,
                                        0x3101774e1c3d72d010efb29c16c476e988bdb47321af3f82e05cc9c6b0360853_big_uint255,
                                        0x327b4e6353c099e41a8ffab9103996b9d29d07da0f1a191aa6fb55c0720c6f54_big_uint255,
                                    }},
                                    {{
                                        0x71c29018dd48d5c557379ea9d4afd80b92788ed509ced6bac47a65ba8b475c_big_uint255,
                                        0x25efdeef6c5ad56834b24cfe03d57360b4335ec902c78ee9348ebaceab726038_big_uint255,
                                        0x109ffe5cd918fcd7da7fdb40d32ac406f453874fda431c35c9e35601bcf708e9_big_uint255,
                                    }},
                                    {{
                                        0x1f4de5d78b4378e0eca49ed94999d8bc91489fadfd896c8affbaa6e2654d18bf_big_uint255,
                                        0x173185e1eaad0664ba1c01b8e417a4422c22a43d622c5df98c11481e205e499e_big_uint255,
                                        0x161a0e8b31a6fd42727dc0a37ae4f715683af35873bd37e78e10abcb0e21fabd_big_uint255,
                                    }},
                                    {{
                                        0x3decab3f42934acc644cc227315ecd6bcee79e5d92dc686823f60e6a3c40a7cd_big_uint255,
                                        0x29d7541d2a4fcdf9c7f144ce1e957a5e5c6d5d064618416817d0ad39708b2807_big_uint255,
                                        0x1d0525558685977d321fe86c05f462ae2e569e6d202bd5c62b0815320454114a_big_uint255,
                                    }},
                                    {{
                                        0x27d1aec0ccc80f71d09d2a9c0b76ee5fe9a87516f0e691a9f5fba360cb79f32_big_uint255,
                                        0x1c28ed68159e54df8296e654b0c1b5872de41557b7b02adc256dcc1600229ba8_big_uint255,
                                        0x15c9cbe29bf4e7d8bae22dd2213c86724e9944ea4b9e34b6681beb1b0972215e_big_uint255,
                                    }},
                                    {{
                                        0xd479e19db4686f5cb1ef9a8331a1ab680c5d3770e9a9a8a7a6ac58f8006c38a_big_uint255,
                                        0x3494f6ecf12d5c3d758c5380652154e26f7f3c888d362ea512da8dc265fc32b0_big_uint255,
                                        0x37ed9343bcc46adb4300f3d8cb88c311383061710836351ded0a146de837966_big_uint255,
                                    }},
                                    {{
                                        0x35548be14e1cbcbd7d2c0e8c4a95e5fc2893daba34197ef41c350ae7072cde4e_big_uint255,
                                        0x34e58327efe8d41b81b66b6c3fad424b2ff9008392909bb90eb10f08462b998b_big_uint255,
                                        0xf55c1223abf50500c4ac4103f679dcfea4eebb368cf64ef3a63ee27146846f_big_uint255,
                                    }},
                                    {{
                                        0x11dd4ab1734f7069498cc390a41b7de375d8968cec91b5c74cef9812e8ee7ce7_big_uint255,
                                        0x1e344f255d7c5e537439e75f9c4ea64dd1fda1b0988e5c83626055859369b43c_big_uint255,
                                        0x147db9afad2d2f7c4249357587faba99a6a38da16fe9ba74ef2f3fc5a0878f44_big_uint255,
                                    }},
                                    {{
                                        0x31774ce29d00f566bd499f181517df231be7205c05e7527d71a1c89cb0e841a7_big_uint255,
                                        0x32bdf60a6685665871f654169996f508be8710c99f3fa6f44a7bc4d2c25fbfd8_big_uint255,
                                        0x2f567f84ec13720611900c4b9e8303f04c8cc5c57daa4d95d9ee009514205e65_big_uint255,
                                    }},
                                    {{
                                        0x2dbd279621e591da57f54459f4160dde2f5c78e478d20f2f4763832e013bc07f_big_uint255,
                                        0x1275fb5ba53b7d2b5322e63f09a48026d684369c8e12241a808085a78ab3a369_big_uint255,
                                        0x1dd0beba925fe1df13f732b03287cad943569d62ec9059afc2c8120655e97d78_big_uint255,
                                    }},
                                    {{
                                        0xa37d78e392a5c8441f98e9dbd51a9151e78fb877885ecb885b0834c50cfea4d_big_uint255,
                                        0x1ebb7e2592122cd16d27e13410b2b48d520d8e99d38c1d86af0ac13565dfeb88_big_uint255,
                                        0x24a6454b0a69c59916d64f532b56226f8d49969432b7d0efc675f599c3bdb64f_big_uint255,
                                    }},
                                    {{
                                        0x269668b3e7835df2f85b82e9ef8647c43205e799135ce669256bf55f07448209_big_uint255,
                                        0x15c87375d4514bbdddbfd84e51f246446f1b16bb58bd4bd9fa2ff57e6aa66057_big_uint255,
                                        0x11ce62bbe1242334c260a67817be908a9422d9b9c6ee96c00772fcc8fc501db6_big_uint255,
                                    }},
                                    {{
                                        0x20348b7d6b381bfd3ac923d60b965086d281d8a654ad5f3210d277789641fe98_big_uint255,
                                        0x1398d090fd1144d1e84798e3a0efa942abfe650947e4a3cfa409ff14b541fae9_big_uint255,
                                        0x2461a1a2d6e3a0b2e5185ae6c844fe2a3b2d85dfb1cf891efc79ae80dd776bed_big_uint255,
                                    }},
                                    {{
                                        0x3e1f1de94c4af008188ba5eaef1da9ab9792ce54eda56bb5a519a65cd808885b_big_uint255,
                                        0x1dee6ead07fbc0fe883f4d397994d75ba3c4f90720e74ae2da13066bc3a7dc3b_big_uint255,
                                        0x287d06396bcb63555cb2ff408ea075cf402b10a3c608043d0cf2e3685ec6e2ad_big_uint255,
                                    }},
                                    {{
                                        0x36d84c953d584607478da6183dc4da71bdbf737d45fb57d5a53badc123ae071c_big_uint255,
                                        0x24c8fd13d2687a9f90c61da26823d4934b350cfa488d528482399e106a70ac74_big_uint255,
                                        0x52e052a6a493457c9476ccc4fd9924e5c7247b98e58a3cfa688c0f8314bea68_big_uint255,
                                    }},
                                    {{
                                        0x2fd32bae8a40ab498f6ba290733bb82504de1be782c1cdf039e2fbc843a01e52_big_uint255,
                                        0x4e8e7d3413c8c8ccfe154dc51f31c7682627c71fa4b50daab27f2a4d2623ea6_big_uint255,
                                        0x20c16d0097cebeb385508b606487baaf3bad515ba8a0b977f15cb50239418e38_big_uint255,
                                    }},
                                    {{
                                        0x34f1df6035aac75204368125b0c4cec107e2f9eb0005517d26d6113e1f366271_big_uint255,
                                        0x375973b59ed7b4bdb33642d20e6364f37a942f9018f6bca5abc10705481425e0_big_uint255,
                                        0x269e8c978803e51d43439b7c18c4260e819e09e7d8c8d38706463bbb811c698c_big_uint255,
                                    }},
                                    {{
                                        0x21be1913f874f3edb88a1f60cd157fcb76ff20b4eb139aae205b5a2764098782_big_uint255,
                                        0x37a0a8ba83db884f721c25027d188c7ab7c7840b7860675b33e1c93e4023927f_big_uint255,
                                        0x56d0e67fde779b7be5f308a3ce119e23e0503e6dabdbbd5189bb44dc6a6f0a4_big_uint255,
                                    }},
                                    {{
                                        0x144723436a329da5644cce96fee4952b066092c36bd12838b4ffd4283cfe82c4_big_uint255,
                                        0xec0b5f14ba50aa2b022d06fbb920a2aafb465b8c7f81fc119371a4cbb6acff7_big_uint255,
                                        0x685de18d9a346a35c44a2a4ac7283d6fe2e4a9dc058bd537700bc2495271721_big_uint255,
                                    }},
                                    {{
                                        0x178dcb74b546adea41afd5d93ef564cb3adb0ef5200201daea0faa5026bb8cbc_big_uint255,
                                        0x1c1dcb1ef6cf5f036ae0030bf78f1643c439843959dd74fa28ea3663735cc923_big_uint255,
                                        0xcfae6c99994c5f702cba3b32a4e38f3764207bfe7cd9bf577633b41843ea138_big_uint255,
                                    }},
                                    {{
                                        0x2838a02558716d2b49c06fb34c49cd820ec71e861caa935f4a303e42030ae3df_big_uint255,
                                        0x2c1944f3ec2852ed6b50fbc4abbc8f284797b36a23b321d2763ef48b1a5a0212_big_uint255,
                                        0x30a218acd109f04657954e82f9faccc477731f4a954cf8ac12d15ebd450e9dcb_big_uint255,
                                    }},
                                    {{
                                        0x2488defa4553fa5bd5afbb5fd28a1e99c585c5f541c6242e702215b2212c1d23_big_uint255,
                                        0x3d0c9d7282245c776daa1655697fa879e470a26fcbb3bea62fa8ff32a4f04e50_big_uint255,
                                        0x33aac46524f32f3556ed16a0912ef27482c2afcacbfb99ced98394b6c0e3765f_big_uint255,
                                    }},
                                    {{
                                        0x1858a5f543ab0a70cb3957e0884b146b42cc3863fba4e034145ab09cc77d428d_big_uint255,
                                        0x2d9d6fae68eff2e79396617207e28dba3d793b1e3739d30e9e9b10644e9f99cd_big_uint255,
                                        0x1747fab074b37cc1ca7dbf7d6dc136740f5d26e30319b3577fc8987f1247caae_big_uint255,
                                    }},
                                    {{
                                        0x38f905db5128f24e498e36a84df5a58ed3c0b0ed8f39336eb792cb634f86b87_big_uint255,
                                        0xfffe42ce4a87a0b3a9ebe7eedf16c0cdb29c959b6e594faa69c0727c6e825f_big_uint255,
                                        0x314c3090cd0a465da95afd515c0771703e4ee2a8eabe8fa405daf8bd49bce458_big_uint255,
                                    }},
                                    {{
                                        0x3e5fb71d9071c658c39fe64392e90bac65bdaf8f723b6790cce7dd7440ce06aa_big_uint255,
                                        0x3e9fe7b8fd0aaa379fa7be0dbd64309607cc5b00474ef6670370e631902e98cd_big_uint255,
                                        0x33ee4f76ff95bd735ec602ee6f4d1664caec27a7c435ead3b4c8df6cb51f010e_big_uint255,
                                    }},
                                    {{
                                        0x1670c2080f2965bed3f49db0b63aef5f562b347235645b921c0132b01cc82130_big_uint255,
                                        0x210565224e2ee64dd479be3a969dc30c65933352ba9b2271a0942bf1bf485743_big_uint255,
                                        0x9a7c6dd48dfbf50b13055b30fe85f934be9518b8af074b88f9de4b1df689616_big_uint255,
                                    }},
                                    {{
                                        0x1f9116811eaadf677e6cb50fb59ce0fab11fa9f0ddf1432403610e1932a7aa1c_big_uint255,
                                        0x19b51a48c225daf9b34611ccc5ba077ebbc0a19cfc9bbbd78ade11cfa655075f_big_uint255,
                                        0x3286d29eb60c3d6204eb534d13f40d1af6364f0fe1622a12ba5fa069886f31fe_big_uint255,
                                    }},
                                    {{
                                        0x9bd403d05db137ea793f10b6dd087a74a78c9b01bcd6f9daf39af2ef57d346e_big_uint255,
                                        0x3a71654023e43363e60889eac50eb1f17c044606886771eaaf851bb2d00b3aeb_big_uint255,
                                        0x3415b94f62c59466f102442b4bae7d6bb348987154cce16bd187525a6fb5b443_big_uint255,
                                    }},
                                    {{
                                        0x3ca35f0fc660092b81f15dd6f0b3d17a16a053480ef2f935fce806dd0d9a3466_big_uint255,
                                        0x26e1360af7fdc62e9be08651c2c5900ed5aefcb0d84b3aa88e354c6658a07863_big_uint255,
                                        0x30d05884174d7a1de9d34c89224d17f3b9dbdfb0793b54c0d2aaaeedcc357bd6_big_uint255,
                                    }},
                                    {{
                                        0x2c7f66f8b0580236f025dd626520049a09e1bfff0e5fd9f69cbc70daf0ac56c4_big_uint255,
                                        0xc5cb9a350d2dc463dd05dbd696e122c6917b76654180c323937dee44c6beb93_big_uint255,
                                        0x14d4d799d43d91b4d09d9c2bfdc13a64b48d18750503324361f9bf7267ec9b92_big_uint255,
                                    }},
                                    {{
                                        0x60c56a884cd6a1d3514f2895816b84e7160df5106e8d031710769be1ac5c04c_big_uint255,
                                        0x23e15f37c21266c86ead998a46e42f6e97fbd5d1c384f51d8b54d051a80d753d_big_uint255,
                                        0x25eb2911034ab6bef4a969653f5cc33e6914b8b6411f064ec01bcf157fea4e55_big_uint255,
                                    }},
                                    {{
                                        0x1e95c04c5057abd1b43a2fbc942b2391d0e0daef873838b3494e6d5fb067a117_big_uint255,
                                        0x1547602fc83558aa1327221fd220fa22bcb1f6ec42edb7cc05eff508c65883cb_big_uint255,
                                        0x16b669eac31e72a9e739fb03fd7ea3882fc5791b157143929ae12fc2fefe8b3d_big_uint255,
                                    }},
                                    {{
                                        0x7034f4e251a65c4423479dc9d5287a341c108e0b56e29a391f9a07a0ca822f1_big_uint255,
                                        0x3fdf9d5731ba040dc568e61b8571ea95ead2e89f0a9856b2d12a7e87e43f5683_big_uint255,
                                        0x33f2cdf6960139a0fb4a3a8127992e2abbd42847728425228a35ee72bd5b01c7_big_uint255,
                                    }},
                                    {{
                                        0x35616d55033d8fc092398f6c58bfc6eaaf2ec9dd500122516f489dbc631457b_big_uint255,
                                        0x1eca80189643df1473e98da93fe58a9576def0d192d4153faebcd1b210c1603f_big_uint255,
                                        0x26223ca4af2d8d878ca5530c3e67ff1c95b50b9c5b8295e19150bc31ef90ba98_big_uint255,
                                    }},
                                    {{
                                        0x19180fa5facb64ee9b4827ccd766622adf12fe80ab17c7395075368e10a2a361_big_uint255,
                                        0x169f165855e097501f25d6b3aae815ce6e8a1c289850936d956657f0ed99446_big_uint255,
                                        0x363a8f891de5974f06bae043bc6a26b4518d217af6590e9318e325fb215cda00_big_uint255,
                                    }},
                                    {{
                                        0x122aaa7c330ddcb57180749e659600a4dfac5dda7b9b68ab0f8b2ee6de350ced_big_uint255,
                                        0xed203defca13ebdf6af805a9f5dbdfef90007df2ad32fb1c83165e837ab5e3f_big_uint255,
                                        0x11cce94bbc7a96e9708e99d3666c0a275329ac4bff42634a5f989ddcfc28fd68_big_uint255,
                                    }},
                                    {{
                                        0x1705663587a03cb11485ac9d01fd10cb1138be1820d26a14e4ab7b1c0fdec8d2_big_uint255,
                                        0x12ad28a60485a2d911639051971f43dd15a0dfd2f8a0de756f0c847fed63ed7d_big_uint255,
                                        0xa9e61cc35eba9374eea117753aaaa93d6b29f550c2c54bce0a6078e05db9475_big_uint255,
                                    }},
                                    {{
                                        0x72c3d62cf006a95dc8b2a53f878bb26fcaf3c28d709a91634f3a09f525054ad_big_uint255,
                                        0x1ce8f168b446f7e797b91677fc46a975d2caa63dc359132c7c9729f5be24a7c_big_uint255,
                                        0xe846a7211efda3d8115b5bf76aab7eac2b6099026fc7504fb81ac4a77c5560d_big_uint255,
                                    }},
                                    {{
                                        0xabb8fd9d6fa3772022fa88800c12bdcbb1234473022cd141213d452255a0f55_big_uint255,
                                        0x1c5d9938bc35a4832e8375dc307dba7a116d2a566e406ab31e8b03a36ec807cf_big_uint255,
                                        0x35bea7ac6f40e0f50f08d325be9f051fd75ada8c03461f4d15b2c5e1a3d72431_big_uint255,
                                    }},
                                    {{
                                        0x419357c205a7e1e028c0f49cbdeab85b82f4db78f1afb1b5568ec1bd2e48cb0_big_uint255,
                                        0x1933e424c788e7466a159f1fe015ac7210f47044d9df6872cdfa227ae4d2190a_big_uint255,
                                        0xde27ccdda95abb3d98db76d6f7f152a08d37ba81758beaf2eddbc58d13e560f_big_uint255,
                                    }},
                                    {{
                                        0x35a312d5d6cbf00d55f097febaf9bd5eac5f2881ebf0afa377e2ba7cdcf2f51_big_uint255,
                                        0xce6f415449ca515e4da9177527c9242adcc988de5e1846d07cdd5284f39f9d0_big_uint255,
                                        0x38fd71543da5c4c0447dc22aa2c1e3744cb84eb1ff17040640b50f5ddf8c8e61_big_uint255,
                                    }},
                                    {{
                                        0x158de859aad53c6a17de455ab067a09ad6cba22f4101d19e77d8a2975c0dc965_big_uint255,
                                        0x2c300588eeae8cbc3814bd1d7646f472ef6b44a60c710bf6100937504e532c8b_big_uint255,
                                        0xb198cf742a029409ac02397b91e2704fa94ecf147909fa8d71ece5087e2cfc3_big_uint255,
                                    }},
                                    {{
                                        0x100b375c21d357d5679d8e6d9eb7bff8edd4575535bf651ba0b1bd83cfb54598_big_uint255,
                                        0x15a474d44590e2b23b8bb1e79f5613f1659e7ae2bce10def0ce1a101eb3e3ce5_big_uint255,
                                        0x2aa20e6642a989e1e6f9814c24f022991c23a7e40af505d4b931079025b7ed4d_big_uint255,
                                    }},
                                    {{
                                        0x196597f2d65c5692706795bf46eb7be96b31647c23441213642ccceedc01ebc4_big_uint255,
                                        0x248291aa516daa0a6cd191c1c651a82f7d1b5f087dcb7cee91a27c488483e2bd_big_uint255,
                                        0x36c02b98ad2722b774aeb131b31bfd087c6a7f2d0a3faa40bd9899e5f270877f_big_uint255,
                                    }},
                                    {{
                                        0x1240e06949a1ad92bd8ae90772b5d8505174182c87a23227aa74b7630dba4195_big_uint255,
                                        0x3b83f7e36f30939a78ec63cb2554aa0669a1bfc1b8b8714c6b8a3958beb6a163_big_uint255,
                                        0x1668b0582ce04f7f5b1e35e1b7cc3e05be23cc2c9e0be9436559193f2a8d102e_big_uint255,
                                    }},
                                    {{
                                        0x26d6a708e9464c85e9c7605e87fb96036fd1fe87379ac43ad560885582e4026d_big_uint255,
                                        0x594fccf1863993b43ad0a13c5fc7a53f59f7d622e7b206d425907243a69e62d_big_uint255,
                                        0x78e4c588b6ddd0fe7ed53a9f25b6ac3c2eac1c63faecc7e916f4d4599051940_big_uint255,
                                    }},
                                    {{
                                        0xf44ea3e14c3e4849ee7a525fe77170b8658a6753680e269c9fd1d12932af69d_big_uint255,
                                        0x2e8567bc9e8e369bdf7748d6c7f677837c601455d4651a2f102b94ff1f951379_big_uint255,
                                        0x37c35b056171982cc7d74e6081fcac2f764f1fe30ee985db306a22b097d51bae_big_uint255,
                                    }},
                                    {{
                                        0x29dbcffd5b55d671c85ca42037ac5e64d2ef42d2704af47a20877e3a5e5f1d9d_big_uint255,
                                        0x201098422e054c1ddcc465411d002d2bc5a824e1c7f4f2ded9443c37bd04a520_big_uint255,
                                        0x7de32ed4c5143430ef43aef100f948ef859ab3793aa52640156f5e7d92cdc84_big_uint255,
                                    }},
                                    {{
                                        0x34e95adcc0c5c34fd38ab9246a04cc1029f678ba53c0f6fd27f8805094e36199_big_uint255,
                                        0x1d5faf157126c599232982356ca0ea7b81d875c01d842b5cd1998a5c470fa623_big_uint255,
                                        0x160a80176bd281e3fa9b82e44063cc7bf86eb81397e51e41fe4745e27c57e1d2_big_uint255,
                                    }},
                                    {{
                                        0x17ecc7f5deb148c542a22d02b098439724910a3bbd4903428c8fc680f31b2406_big_uint255,
                                        0x20a6aae17f822bc7035da3b8931896c82152346f2a43ab4e0029dbf0101b3d_big_uint255,
                                        0x9ea0ec10c0e77b9385a58ccd5ecc3c88b5bed58af72a6d87bb446e14fa7c8d6_big_uint255,
                                    }},
                                }};
                    };
                    template<>
                    struct poseidon_constants<
                        nil::crypto3::algebra::fields::alt_bn128_scalar_field<254>> {
                        using FieldType =
                            nil::crypto3::algebra::fields::alt_bn128_scalar_field<254>;
                        constexpr static const std::size_t state_size = 3;
                        constexpr static const std::size_t full_rounds_amount = 8;
                        constexpr static const std::size_t partial_rounds_amount = 57;
                        constexpr static const std::size_t total_rounds_amount =
                            full_rounds_amount + partial_rounds_amount;
                        constexpr static const std::size_t sbox_alpha = 5;
                        constexpr static bool pasta_version = false;

                        constexpr static const std::array<
                            std::array<typename FieldType::value_type, state_size>, state_size>
                            mds = {
                                {{{0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b_big_uint255,
                                   0x16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0_big_uint255,
                                   0x2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d_big_uint255}},
                                 {{0x2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771_big_uint255,
                                   0x2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23_big_uint255,
                                   0x101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa_big_uint255}},
                                 {{0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7_big_uint255,
                                   0x176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911_big_uint255,
                                   0x19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0_big_uint255}}}};

                        constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, total_rounds_amount> round_constant =
                            {{{{0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e_big_uint255,
                                0x00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864_big_uint255,
                                0x08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5_big_uint255}},
                              {{0x2f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d0_big_uint255,
                                0x2b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf2_big_uint255,
                                0x0319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa_big_uint255}},
                              {{0x28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d_big_uint255,
                                0x2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78_big_uint255,
                                0x234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc632_big_uint255}},
                              {{0x15b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d428_big_uint255,
                                0x0dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f6_big_uint255,
                                0x1bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c_big_uint255}},
                              {{0x10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559_big_uint255,
                                0x1f6d48149b8e7f7d9b257d8ed5fbbaf42932498075fed0ace88a9eb81f5627f6_big_uint255,
                                0x1d9655f652309014d29e00ef35a2089bfff8dc1c816f0dc9ca34bdb5460c8705_big_uint255}},
                              {{0x04df5a56ff95bcafb051f7b1cd43a99ba731ff67e47032058fe3d4185697cc7d_big_uint255,
                                0x0672d995f8fff640151b3d290cedaf148690a10a8c8424a7f6ec282b6e4be828_big_uint255,
                                0x099952b414884454b21200d7ffafdd5f0c9a9dcc06f2708e9fc1d8209b5c75b9_big_uint255}},
                              {{0x052cba2255dfd00c7c483143ba8d469448e43586a9b4cd9183fd0e843a6b9fa6_big_uint255,
                                0x0b8badee690adb8eb0bd74712b7999af82de55707251ad7716077cb93c464ddc_big_uint255,
                                0x119b1590f13307af5a1ee651020c07c749c15d60683a8050b963d0a8e4b2bdd1_big_uint255}},
                              {{0x03150b7cd6d5d17b2529d36be0f67b832c4acfc884ef4ee5ce15be0bfb4a8d09_big_uint255,
                                0x2cc6182c5e14546e3cf1951f173912355374efb83d80898abe69cb317c9ea565_big_uint255,
                                0x005032551e6378c450cfe129a404b3764218cadedac14e2b92d2cd73111bf0f9_big_uint255}},
                              {{0x233237e3289baa34bb147e972ebcb9516469c399fcc069fb88f9da2cc28276b5_big_uint255,
                                0x05c8f4f4ebd4a6e3c980d31674bfbe6323037f21b34ae5a4e80c2d4c24d60280_big_uint255,
                                0x0a7b1db13042d396ba05d818a319f25252bcf35ef3aeed91ee1f09b2590fc65b_big_uint255}},
                              {{0x2a73b71f9b210cf5b14296572c9d32dbf156e2b086ff47dc5df542365a404ec0_big_uint255,
                                0x1ac9b0417abcc9a1935107e9ffc91dc3ec18f2c4dbe7f22976a760bb5c50c460_big_uint255,
                                0x12c0339ae08374823fabb076707ef479269f3e4d6cb104349015ee046dc93fc0_big_uint255}},
                              {{0x0b7475b102a165ad7f5b18db4e1e704f52900aa3253baac68246682e56e9a28e_big_uint255,
                                0x037c2849e191ca3edb1c5e49f6e8b8917c843e379366f2ea32ab3aa88d7f8448_big_uint255,
                                0x05a6811f8556f014e92674661e217e9bd5206c5c93a07dc145fdb176a716346f_big_uint255}},
                              {{0x29a795e7d98028946e947b75d54e9f044076e87a7b2883b47b675ef5f38bd66e_big_uint255,
                                0x20439a0c84b322eb45a3857afc18f5826e8c7382c8a1585c507be199981fd22f_big_uint255,
                                0x2e0ba8d94d9ecf4a94ec2050c7371ff1bb50f27799a84b6d4a2a6f2a0982c887_big_uint255}},
                              {{0x143fd115ce08fb27ca38eb7cce822b4517822cd2109048d2e6d0ddcca17d71c8_big_uint255,
                                0x0c64cbecb1c734b857968dbbdcf813cdf8611659323dbcbfc84323623be9caf1_big_uint255,
                                0x028a305847c683f646fca925c163ff5ae74f348d62c2b670f1426cef9403da53_big_uint255}},
                              {{0x2e4ef510ff0b6fda5fa940ab4c4380f26a6bcb64d89427b824d6755b5db9e30c_big_uint255,
                                0x0081c95bc43384e663d79270c956ce3b8925b4f6d033b078b96384f50579400e_big_uint255,
                                0x2ed5f0c91cbd9749187e2fade687e05ee2491b349c039a0bba8a9f4023a0bb38_big_uint255}},
                              {{0x30509991f88da3504bbf374ed5aae2f03448a22c76234c8c990f01f33a735206_big_uint255,
                                0x1c3f20fd55409a53221b7c4d49a356b9f0a1119fb2067b41a7529094424ec6ad_big_uint255,
                                0x10b4e7f3ab5df003049514459b6e18eec46bb2213e8e131e170887b47ddcb96c_big_uint255}},
                              {{0x2a1982979c3ff7f43ddd543d891c2abddd80f804c077d775039aa3502e43adef_big_uint255,
                                0x1c74ee64f15e1db6feddbead56d6d55dba431ebc396c9af95cad0f1315bd5c91_big_uint255,
                                0x07533ec850ba7f98eab9303cace01b4b9e4f2e8b82708cfa9c2fe45a0ae146a0_big_uint255}},
                              {{0x21576b438e500449a151e4eeaf17b154285c68f42d42c1808a11abf3764c0750_big_uint255,
                                0x2f17c0559b8fe79608ad5ca193d62f10bce8384c815f0906743d6930836d4a9e_big_uint255,
                                0x2d477e3862d07708a79e8aae946170bc9775a4201318474ae665b0b1b7e2730e_big_uint255}},
                              {{0x162f5243967064c390e095577984f291afba2266c38f5abcd89be0f5b2747eab_big_uint255,
                                0x2b4cb233ede9ba48264ecd2c8ae50d1ad7a8596a87f29f8a7777a70092393311_big_uint255,
                                0x2c8fbcb2dd8573dc1dbaf8f4622854776db2eece6d85c4cf4254e7c35e03b07a_big_uint255}},
                              {{0x1d6f347725e4816af2ff453f0cd56b199e1b61e9f601e9ade5e88db870949da9_big_uint255,
                                0x204b0c397f4ebe71ebc2d8b3df5b913df9e6ac02b68d31324cd49af5c4565529_big_uint255,
                                0x0c4cb9dc3c4fd8174f1149b3c63c3c2f9ecb827cd7dc25534ff8fb75bc79c502_big_uint255}},
                              {{0x174ad61a1448c899a25416474f4930301e5c49475279e0639a616ddc45bc7b54_big_uint255,
                                0x1a96177bcf4d8d89f759df4ec2f3cde2eaaa28c177cc0fa13a9816d49a38d2ef_big_uint255,
                                0x066d04b24331d71cd0ef8054bc60c4ff05202c126a233c1a8242ace360b8a30a_big_uint255}},
                              {{0x2a4c4fc6ec0b0cf52195782871c6dd3b381cc65f72e02ad527037a62aa1bd804_big_uint255,
                                0x13ab2d136ccf37d447e9f2e14a7cedc95e727f8446f6d9d7e55afc01219fd649_big_uint255,
                                0x1121552fca26061619d24d843dc82769c1b04fcec26f55194c2e3e869acc6a9a_big_uint255}},
                              {{0x00ef653322b13d6c889bc81715c37d77a6cd267d595c4a8909a5546c7c97cff1_big_uint255,
                                0x0e25483e45a665208b261d8ba74051e6400c776d652595d9845aca35d8a397d3_big_uint255,
                                0x29f536dcb9dd7682245264659e15d88e395ac3d4dde92d8c46448db979eeba89_big_uint255}},
                              {{0x2a56ef9f2c53febadfda33575dbdbd885a124e2780bbea170e456baace0fa5be_big_uint255,
                                0x1c8361c78eb5cf5decfb7a2d17b5c409f2ae2999a46762e8ee416240a8cb9af1_big_uint255,
                                0x151aff5f38b20a0fc0473089aaf0206b83e8e68a764507bfd3d0ab4be74319c5_big_uint255}},
                              {{0x04c6187e41ed881dc1b239c88f7f9d43a9f52fc8c8b6cdd1e76e47615b51f100_big_uint255,
                                0x13b37bd80f4d27fb10d84331f6fb6d534b81c61ed15776449e801b7ddc9c2967_big_uint255,
                                0x01a5c536273c2d9df578bfbd32c17b7a2ce3664c2a52032c9321ceb1c4e8a8e4_big_uint255}},
                              {{0x2ab3561834ca73835ad05f5d7acb950b4a9a2c666b9726da832239065b7c3b02_big_uint255,
                                0x1d4d8ec291e720db200fe6d686c0d613acaf6af4e95d3bf69f7ed516a597b646_big_uint255,
                                0x041294d2cc484d228f5784fe7919fd2bb925351240a04b711514c9c80b65af1d_big_uint255}},
                              {{0x154ac98e01708c611c4fa715991f004898f57939d126e392042971dd90e81fc6_big_uint255,
                                0x0b339d8acca7d4f83eedd84093aef51050b3684c88f8b0b04524563bc6ea4da4_big_uint255,
                                0x0955e49e6610c94254a4f84cfbab344598f0e71eaff4a7dd81ed95b50839c82e_big_uint255}},
                              {{0x06746a6156eba54426b9e22206f15abca9a6f41e6f535c6f3525401ea0654626_big_uint255,
                                0x0f18f5a0ecd1423c496f3820c549c27838e5790e2bd0a196ac917c7ff32077fb_big_uint255,
                                0x04f6eeca1751f7308ac59eff5beb261e4bb563583ede7bc92a738223d6f76e13_big_uint255}},
                              {{0x2b56973364c4c4f5c1a3ec4da3cdce038811eb116fb3e45bc1768d26fc0b3758_big_uint255,
                                0x123769dd49d5b054dcd76b89804b1bcb8e1392b385716a5d83feb65d437f29ef_big_uint255,
                                0x2147b424fc48c80a88ee52b91169aacea989f6446471150994257b2fb01c63e9_big_uint255}},
                              {{0x0fdc1f58548b85701a6c5505ea332a29647e6f34ad4243c2ea54ad897cebe54d_big_uint255,
                                0x12373a8251fea004df68abcf0f7786d4bceff28c5dbbe0c3944f685cc0a0b1f2_big_uint255,
                                0x21e4f4ea5f35f85bad7ea52ff742c9e8a642756b6af44203dd8a1f35c1a90035_big_uint255}},
                              {{0x16243916d69d2ca3dfb4722224d4c462b57366492f45e90d8a81934f1bc3b147_big_uint255,
                                0x1efbe46dd7a578b4f66f9adbc88b4378abc21566e1a0453ca13a4159cac04ac2_big_uint255,
                                0x07ea5e8537cf5dd08886020e23a7f387d468d5525be66f853b672cc96a88969a_big_uint255}},
                              {{0x05a8c4f9968b8aa3b7b478a30f9a5b63650f19a75e7ce11ca9fe16c0b76c00bc_big_uint255,
                                0x20f057712cc21654fbfe59bd345e8dac3f7818c701b9c7882d9d57b72a32e83f_big_uint255,
                                0x04a12ededa9dfd689672f8c67fee31636dcd8e88d01d49019bd90b33eb33db69_big_uint255}},
                              {{0x27e88d8c15f37dcee44f1e5425a51decbd136ce5091a6767e49ec9544ccd101a_big_uint255, 0x2feed17b84285ed9b8a5c8c5e95a41f66e096619a7703223176c41ee433de4d1_big_uint255,
                                0x1ed7cc76edf45c7c404241420f729cf394e5942911312a0d6972b8bd53aff2b8_big_uint255}},
                              {{0x15742e99b9bfa323157ff8c586f5660eac6783476144cdcadf2874be45466b1a_big_uint255,
                                0x1aac285387f65e82c895fc6887ddf40577107454c6ec0317284f033f27d0c785_big_uint255,
                                0x25851c3c845d4790f9ddadbdb6057357832e2e7a49775f71ec75a96554d67c77_big_uint255}},
                              {{0x15a5821565cc2ec2ce78457db197edf353b7ebba2c5523370ddccc3d9f146a67_big_uint255,
                                0x2411d57a4813b9980efa7e31a1db5966dcf64f36044277502f15485f28c71727_big_uint255,
                                0x002e6f8d6520cd4713e335b8c0b6d2e647e9a98e12f4cd2558828b5ef6cb4c9b_big_uint255}},
                              {{0x2ff7bc8f4380cde997da00b616b0fcd1af8f0e91e2fe1ed7398834609e0315d2_big_uint255,
                                0x00b9831b948525595ee02724471bcd182e9521f6b7bb68f1e93be4febb0d3cbe_big_uint255,
                                0x0a2f53768b8ebf6a86913b0e57c04e011ca408648a4743a87d77adbf0c9c3512_big_uint255}},
                              {{0x00248156142fd0373a479f91ff239e960f599ff7e94be69b7f2a290305e1198d_big_uint255,
                                0x171d5620b87bfb1328cf8c02ab3f0c9a397196aa6a542c2350eb512a2b2bcda9_big_uint255,
                                0x170a4f55536f7dc970087c7c10d6fad760c952172dd54dd99d1045e4ec34a808_big_uint255}},
                              {{0x29aba33f799fe66c2ef3134aea04336ecc37e38c1cd211ba482eca17e2dbfae1_big_uint255,
                                0x1e9bc179a4fdd758fdd1bb1945088d47e70d114a03f6a0e8b5ba650369e64973_big_uint255,
                                0x1dd269799b660fad58f7f4892dfb0b5afeaad869a9c4b44f9c9e1c43bdaf8f09_big_uint255}},
                              {{0x22cdbc8b70117ad1401181d02e15459e7ccd426fe869c7c95d1dd2cb0f24af38_big_uint255,
                                0x0ef042e454771c533a9f57a55c503fcefd3150f52ed94a7cd5ba93b9c7dacefd_big_uint255,
                                0x11609e06ad6c8fe2f287f3036037e8851318e8b08a0359a03b304ffca62e8284_big_uint255}},
                              {{0x1166d9e554616dba9e753eea427c17b7fecd58c076dfe42708b08f5b783aa9af_big_uint255,
                                0x2de52989431a859593413026354413db177fbf4cd2ac0b56f855a888357ee466_big_uint255,
                                0x3006eb4ffc7a85819a6da492f3a8ac1df51aee5b17b8e89d74bf01cf5f71e9ad_big_uint255}},
                              {{0x2af41fbb61ba8a80fdcf6fff9e3f6f422993fe8f0a4639f962344c8225145086_big_uint255,
                                0x119e684de476155fe5a6b41a8ebc85db8718ab27889e85e781b214bace4827c3_big_uint255,
                                0x1835b786e2e8925e188bea59ae363537b51248c23828f047cff784b97b3fd800_big_uint255}},
                              {{0x28201a34c594dfa34d794996c6433a20d152bac2a7905c926c40e285ab32eeb6_big_uint255,
                                0x083efd7a27d1751094e80fefaf78b000864c82eb571187724a761f88c22cc4e7_big_uint255,
                                0x0b6f88a3577199526158e61ceea27be811c16df7774dd8519e079564f61fd13b_big_uint255}},
                              {{0x0ec868e6d15e51d9644f66e1d6471a94589511ca00d29e1014390e6ee4254f5b_big_uint255,
                                0x2af33e3f866771271ac0c9b3ed2e1142ecd3e74b939cd40d00d937ab84c98591_big_uint255,
                                0x0b520211f904b5e7d09b5d961c6ace7734568c547dd6858b364ce5e47951f178_big_uint255}},
                              {{0x0b2d722d0919a1aad8db58f10062a92ea0c56ac4270e822cca228620188a1d40_big_uint255,
                                0x1f790d4d7f8cf094d980ceb37c2453e957b54a9991ca38bbe0061d1ed6e562d4_big_uint255,
                                0x0171eb95dfbf7d1eaea97cd385f780150885c16235a2a6a8da92ceb01e504233_big_uint255}},
                              {{0x0c2d0e3b5fd57549329bf6885da66b9b790b40defd2c8650762305381b168873_big_uint255,
                                0x1162fb28689c27154e5a8228b4e72b377cbcafa589e283c35d3803054407a18d_big_uint255,
                                0x2f1459b65dee441b64ad386a91e8310f282c5a92a89e19921623ef8249711bc0_big_uint255}},
                              {{0x1e6ff3216b688c3d996d74367d5cd4c1bc489d46754eb712c243f70d1b53cfbb_big_uint255,
                                0x01ca8be73832b8d0681487d27d157802d741a6f36cdc2a0576881f9326478875_big_uint255,
                                0x1f7735706ffe9fc586f976d5bdf223dc680286080b10cea00b9b5de315f9650e_big_uint255}},
                              {{0x2522b60f4ea3307640a0c2dce041fba921ac10a3d5f096ef4745ca838285f019_big_uint255,
                                0x23f0bee001b1029d5255075ddc957f833418cad4f52b6c3f8ce16c235572575b_big_uint255,
                                0x2bc1ae8b8ddbb81fcaac2d44555ed5685d142633e9df905f66d9401093082d59_big_uint255}},
                              {{0x0f9406b8296564a37304507b8dba3ed162371273a07b1fc98011fcd6ad72205f_big_uint255,
                                0x2360a8eb0cc7defa67b72998de90714e17e75b174a52ee4acb126c8cd995f0a8_big_uint255,
                                0x15871a5cddead976804c803cbaef255eb4815a5e96df8b006dcbbc2767f88948_big_uint255}},
                              {{0x193a56766998ee9e0a8652dd2f3b1da0362f4f54f72379544f957ccdeefb420f_big_uint255,
                                0x2a394a43934f86982f9be56ff4fab1703b2e63c8ad334834e4309805e777ae0f_big_uint255,
                                0x1859954cfeb8695f3e8b635dcb345192892cd11223443ba7b4166e8876c0d142_big_uint255}},
                              {{0x04e1181763050e58013444dbcb99f1902b11bc25d90bbdca408d3819f4fed32b_big_uint255,
                                0x0fdb253dee83869d40c335ea64de8c5bb10eb82db08b5e8b1f5e5552bfd05f23_big_uint255,
                                0x058cbe8a9a5027bdaa4efb623adead6275f08686f1c08984a9d7c5bae9b4f1c0_big_uint255}},
                              {{0x1382edce9971e186497eadb1aeb1f52b23b4b83bef023ab0d15228b4cceca59a_big_uint255,
                                0x03464990f045c6ee0819ca51fd11b0be7f61b8eb99f14b77e1e6634601d9e8b5_big_uint255,
                                0x23f7bfc8720dc296fff33b41f98ff83c6fcab4605db2eb5aaa5bc137aeb70a58_big_uint255}},
                              {{0x0a59a158e3eec2117e6e94e7f0e9decf18c3ffd5e1531a9219636158bbaf62f2_big_uint255,
                                0x06ec54c80381c052b58bf23b312ffd3ce2c4eba065420af8f4c23ed0075fd07b_big_uint255,
                                0x118872dc832e0eb5476b56648e867ec8b09340f7a7bcb1b4962f0ff9ed1f9d01_big_uint255}},
                              {{0x13d69fa127d834165ad5c7cba7ad59ed52e0b0f0e42d7fea95e1906b520921b1_big_uint255,
                                0x169a177f63ea681270b1c6877a73d21bde143942fb71dc55fd8a49f19f10c77b_big_uint255,
                                0x04ef51591c6ead97ef42f287adce40d93abeb032b922f66ffb7e9a5a7450544d_big_uint255}},
                              {{0x256e175a1dc079390ecd7ca703fb2e3b19ec61805d4f03ced5f45ee6dd0f69ec_big_uint255,
                                0x30102d28636abd5fe5f2af412ff6004f75cc360d3205dd2da002813d3e2ceeb2_big_uint255,
                                0x10998e42dfcd3bbf1c0714bc73eb1bf40443a3fa99bef4a31fd31be182fcc792_big_uint255}},
                              {{0x193edd8e9fcf3d7625fa7d24b598a1d89f3362eaf4d582efecad76f879e36860_big_uint255,
                                0x18168afd34f2d915d0368ce80b7b3347d1c7a561ce611425f2664d7aa51f0b5d_big_uint255,
                                0x29383c01ebd3b6ab0c017656ebe658b6a328ec77bc33626e29e2e95b33ea6111_big_uint255}},
                              {{0x10646d2f2603de39a1f4ae5e7771a64a702db6e86fb76ab600bf573f9010c711_big_uint255,
                                0x0beb5e07d1b27145f575f1395a55bf132f90c25b40da7b3864d0242dcb1117fb_big_uint255,
                                0x16d685252078c133dc0d3ecad62b5c8830f95bb2e54b59abdffbf018d96fa336_big_uint255}},
                              {{0x0a6abd1d833938f33c74154e0404b4b40a555bbbec21ddfafd672dd62047f01a_big_uint255,
                                0x1a679f5d36eb7b5c8ea12a4c2dedc8feb12dffeec450317270a6f19b34cf1860_big_uint255,
                                0x0980fb233bd456c23974d50e0ebfde4726a423eada4e8f6ffbc7592e3f1b93d6_big_uint255}},
                              {{0x161b42232e61b84cbf1810af93a38fc0cece3d5628c9282003ebacb5c312c72b_big_uint255,
                                0x0ada10a90c7f0520950f7d47a60d5e6a493f09787f1564e5d09203db47de1a0b_big_uint255,
                                0x1a730d372310ba82320345a29ac4238ed3f07a8a2b4e121bb50ddb9af407f451_big_uint255}},
                              {{0x2c8120f268ef054f817064c369dda7ea908377feaba5c4dffbda10ef58e8c556_big_uint255,
                                0x1c7c8824f758753fa57c00789c684217b930e95313bcb73e6e7b8649a4968f70_big_uint255,
                                0x2cd9ed31f5f8691c8e39e4077a74faa0f400ad8b491eb3f7b47b27fa3fd1cf77_big_uint255}},
                              {{0x23ff4f9d46813457cf60d92f57618399a5e022ac321ca550854ae23918a22eea_big_uint255,
                                0x09945a5d147a4f66ceece6405dddd9d0af5a2c5103529407dff1ea58f180426d_big_uint255,
                                0x188d9c528025d4c2b67660c6b771b90f7c7da6eaa29d3f268a6dd223ec6fc630_big_uint255}},
                              {{0x3050e37996596b7f81f68311431d8734dba7d926d3633595e0c0d8ddf4f0f47f_big_uint255,
                                0x15af1169396830a91600ca8102c35c426ceae5461e3f95d89d829518d30afd78_big_uint255,
                                0x1da6d09885432ea9a06d9f37f873d985dae933e351466b2904284da3320d8acc_big_uint255}},
                              {{0x2796ea90d269af29f5f8acf33921124e4e4fad3dbe658945e546ee411ddaa9cb_big_uint255,
                                0x202d7dd1da0f6b4b0325c8b3307742f01e15612ec8e9304a7cb0319e01d32d60_big_uint255,
                                0x096d6790d05bb759156a952ba263d672a2d7f9c788f4c831a29dace4c0f8be5f_big_uint255}},
                              {{0x054efa1f65b0fce283808965275d877b438da23ce5b13e1963798cb1447d25a4_big_uint255,
                                0x1b162f83d917e93edb3308c29802deb9d8aa690113b2e14864ccf6e18e4165f1_big_uint255,
                                0x21e5241e12564dd6fd9f1cdd2a0de39eedfefc1466cc568ec5ceb745a0506edc_big_uint255}},
                              {{0x1cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf08_big_uint255,
                                0x0f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb24100_big_uint255,
                                0x1671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c2320_big_uint255}},
                              {{0x0fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870_big_uint255,
                                0x193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba_big_uint255, 0x102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f8_big_uint255}},
                              {{0x0fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1_big_uint255,
                                0x216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d22_big_uint255,
                                0x1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161_big_uint255}}}};
                    };
                }  // namespace detail
            }  // namespace components
        }  // namespace bbf
    }  // namespace blueprint
}  // namespace nil

#endif  // CRYPTO3_BBF_PLONK_DETAIL_POSEIDON_CONSTANTS_HPP