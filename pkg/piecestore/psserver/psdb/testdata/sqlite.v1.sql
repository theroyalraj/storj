CREATE TABLE `ttl` (`id` BLOB UNIQUE, `created` INT(10), `expires` INT(10), `size` INT(10));
CREATE TABLE `bandwidth_agreements` (`satellite` BLOB, `agreement` BLOB, `signature` BLOB, `uplink` BLOB, `serial_num` BLOB, `total` INT(10), `max_size` INT(10), `created_utc_sec`	INT(10), `status` TEXT, `expiration_utc_sec` INT(10), `action` INT(10), `daystart_utc_sec` INT(10));
CREATE INDEX idx_ttl_expires ON ttl (expires);
INSERT INTO ttl VALUES(1,2,3,4);
INSERT INTO bandwidth_agreements VALUES(
    X'0fac57151affd454b6884e2ee085097ef9581edea7ccfe6b6ba6401beac06500',
    X'0a8a070a200fac57151affd454b6884e2ee085097ef9581edea7ccfe6b6ba6401beac06500122018964640433f24595097466bd08d35bdd1ddf5082f75a821613a6c8b445e0000208fbda2e5052a2430343039363865662d653435342d343432342d616131662d336437333635666365393031388f96b5e30542e6023082016230820108a003020102021100b8be6e42d5b98e0757cda2fa5088e3dd300a06082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031303130313030303030305a180f30303031303130313030303030305a3010310e300c060355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d03010703420004e94b91d488fd492e0097199632ce29dc1e0ada0edd03387d63b5f64e3108519eaaa391cafe0e74a5ae0c39f3056a630a57d55e05c2b160461541aa2bdf1f5978a33f303d300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000300a06082a8648ce3d040302034800304502202ed2c4bdfab3a56cd7694e0e67cadaa48d2e6ae3a87dbd4e310395190374e3a0022100eba5c24ed07e4e539948bbd6bdcdc6000633a95373380e6bddc23b2e43f4288142e0023082015c30820101a003020102021100c387ca34d032179981de0f1c642ab820300a06082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031303130313030303030305a180f30303031303130313030303030305a3010310e300c060355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d03010703420004d5c4e88ea884c28d98ed162f9c43d6e056e83a6d9315dc08b2a63e5416867a1e3a2c2f670e4a47e5b6cef6b9df9c0eb46debbf7a70557065479da617ce50b1aaa3383036300e0603551d0f0101ff04040302020430130603551d25040c300a06082b06010505070301300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100a078a46470e233cd315329725435357fc93f778bb85cdab00a2178660fabf48f022100ed4d90f661ccb7abb7c996626179707c00497957c75dfb8db1ed17d2d80b4cf04a46304402203288c3a91734196d64dbb44390204899e7fb46fb569910665ce7ef924aadf2b502203565082f9b370c1cf89e854fece05033f9ab6e0d3d6dc08b6defb729ea6574301080f8a2011a20555937661ba23a14e4f32e69ba8b8d503f046bc94f2622b50ceae5327bf1f90022e6023082016230820107a00302010202104edd0ae5652847fb1293a10892c25f24300a06082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031303130313030303030305a180f30303031303130313030303030305a3010310e300c060355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d030107034200041ed2af8a599e9ed6ea5c85c92a09a42b4530fd1fda0ef481d891ae08c9cea684046073f57f50ee23c1def0ca9158ba470a0f445ffe99d977a60f6e6fc6f6a57aa33f303d300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000300a06082a8648ce3d04030203490030460221009585d52e9e12223b11153d8d187349f1f591f6acad41594635e51d359f00d39e0221009a11bd9e81d94a4ee2c3c7adbe362df1c47d3ef4f8ba11d94971f9d4eb59eb1b22df023082015b30820100a00302010202106861fa849f76dabd1a66a3d2a5fb4eb7300a06082a8648ce3d0403023010310e300c060355040a130553746f726a3022180f30303031303130313030303030305a180f30303031303130313030303030305a3010310e300c060355040a130553746f726a3059301306072a8648ce3d020106082a8648ce3d03010703420004ea0ea4bda75425e4277a3a8f0b2fb7adc718c4bad684b082f798b1a2fc6847949719f2230a8b0ef70ea03d18acba93e4b6a3b9b664abc0383a57ec6b8c442905a3383036300e0603551d0f0101ff04040302020430130603551d25040c300a06082b06010505070301300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203490030460221009795c5e7a3cc6ff459cb5816cc5f96cce1894c6ab60c8df3bfe5066cd8aede22022100f61dc807be119c4248de952f5e5ab2e0cf447992749ed3cbe75f351819433e2e2a46304402207eb5bf07d082b299351e89633e82f2e9514f2982d3fddcacf2e331e28c61c95202200c1790520d2983bb768b97f0ed772262ceed5230ecd42a7ba06b7f4a32a1fdcd',
    X'7369676e6174757265', 
    X'18964640433F24595097466BD08D35BDD1DDF5082F75A821613A6C8B445E0000',
    '040968ef-e454-4424-aa1f-3d7365fce901',
    2669568,
    0,
    1550666511,
    "UNSENT",
    1554554511,
    0,
    1550620800
);