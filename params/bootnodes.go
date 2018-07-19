// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

var MainnetBootnodes = []string{
	"enode://3351d107d6be73c6f5133ab65e122b56b4f8415f4f356331a83a9c7e2fa77bdceb1b8cb588ca1983c782a0a7ed1176af251fba6454364a66c86d5ac93a0ca81b@120.77.71.197:20001", // [1]
	"enode://6970909a829b7af5a843282954086f3451c6945d6ef7cfb14f6830462a9a180c7a356ec7e9ca706c2fa12c908ea9f4d78cc906372663dedc6df482c0f83c4e90@13.251.86.76:20002", // [2]
	"enode://02c56e2a4a4a2bcda8e0560cba50a262922d71d47106d2eb93cc85c58b7d326ac7d7e96ed9fd4ae4c996e9ae9625124b00edaa4132d9acf9734fbc965ad25fec@47.75.72.46:20003", // [3]

}

var MainnetMasternodes = []string{
	"enode://3351d107d6be73c6f5133ab65e122b56b4f8415f4f356331a83a9c7e2fa77bdceb1b8cb588ca1983c782a0a7ed1176af251fba6454364a66c86d5ac93a0ca81b@0.0.0.0:20001", // [1]
	"enode://6970909a829b7af5a843282954086f3451c6945d6ef7cfb14f6830462a9a180c7a356ec7e9ca706c2fa12c908ea9f4d78cc906372663dedc6df482c0f83c4e90@0.0.0.0:20002", // [2]
	"enode://02c56e2a4a4a2bcda8e0560cba50a262922d71d47106d2eb93cc85c58b7d326ac7d7e96ed9fd4ae4c996e9ae9625124b00edaa4132d9acf9734fbc965ad25fec@0.0.0.0:20003", // [3]
	//"enode://593a46c1827b52eebb27b313de2ead4c48a11313875c3887b0e0a28a2eac6349f0bdf17394ae7b2e0dfc659344706e0126f40c89780fbe671e1ed438fd6a49bc@0.0.0.0:20004", // [4]
	//"enode://a67c00f5261a537f8face324d0f4df0e2a6760ba278957acd1e7bc830e6af6c33a5a3b2f2b694e1aef28aea58eb082e34f42a0dae0e2a6e79da13ff35548dc5d@0.0.0.0:20005", // [5]
	//"enode://838d6188a8048d6e8e8a362c1847e566a7860d0faf287b0b5474b560695affe6ebab12d0136f1a0cae9b315c1d10bd27dc709b35fda6b9c02e899a9f359a105a@0.0.0.0:20006", // [6]
	//"enode://2873416ac49feecd7e56743a888688ddb33a6d3ec74b6c4580a5f8650016f2a8d35722a06ed3b498990c1d73acd2d9f43511285bd721f1c07a3068816800f117@0.0.0.0:20007", // [7]
	//"enode://b6b53832481588f465fb42eff3110f926cad1f62ed101d79363c1e07e549282b1251e72371c49c2dc7aa00ed5914db7726b5f2504e46a05f2fd385d24f6a74ca@0.0.0.0:20008", // [8]
	//"enode://31913ce2c2c367c168aa942cedb7430f048f8ed2ad3a54dc5af625a2879893d76b2115a50f28ce8cd39396235afcdf7281b9d4c2f73324fa5948bc4360d1c53d@0.0.0.0:20009", // [9]
	//"enode://598dd425bc42c321b5c53edb9bae4bc1e3d1ae6c6bc9415030898a1838c2d13b0a71177fef88c76bd7b7a0705230bbf262ba1a2d1029131187fd2a9589581739@0.0.0.0:20010", // [10]
	//"enode://b603195abdc80206ff6bace405349803458d647b2f820698ca47d71c15975999518697362f1a81233c657b703670e153fefa22478596647cdf508ebd433f06d9@0.0.0.0:20011", // [11]
	//"enode://10f2dda7e5a30b090eb88582ae8e8d503bf0c670ea064ee955ad4eb5833f25f9250e0d38b22a5b64e0415a2c2d617f4b2ad735a4bb88de294df360e98ff803a1@0.0.0.0:20012", // [12]
	//"enode://494e245225990dd348cfbd803d39f88d4f49e907a2fc5bcbe7840153b78845cd3158d1570378189fdea243eb55140ce86e520fdc2b64ad78faabf0328be9051c@0.0.0.0:20013", // [13]
	//"enode://f3b5d979e17f745d19d1eed11007070fdbbeb4f339a2c32074c8e9c0408acd1f7c6ed457cde3b3346a8e201491ce396933878b9486a0b4328e37754e9b12f87a@0.0.0.0:20014", // [14]
	//"enode://0a31ebaafbaeebd957d5d176816230d3a17ef62a01a780a74638d4a3adbc60b366c6543ae20e101d61a4b7f432d1848bfe14f1537f6589ec18a469f4fae3ceba@0.0.0.0:20015", // [15]
	//"enode://8fd0c28c33132fa047ee331673e865525c2a6a7c36e1c023d24a74356e1c73dff87f8920f8d1a7e871af6660f6b1faa68c0569d3e06ef2f55bca8ba7fbe74dfc@0.0.0.0:20016", // [16]
	//"enode://9ca93a302c2c55923818b4c3973b1559572a66a8ef83595593870cd04affd519e9af476a8e873c7c6d2e503c9be8c3556bea120c57874c2390e644c17f583e2c@0.0.0.0:20017", // [17]
	//"enode://598a148cfdadf1a80fdbfe312eaa9af81185bd107124aa69ea2787c33e898a784bddc0dd7d1dfbb98813700e57daea8b4956d7fa66d5f861d998a228f3a3fda5@0.0.0.0:20018", // [18]
	//"enode://ff5768d9967cab569cd0777eca56ba4d16554a07dfcb075a46badf1c1c1637eb86c8ba7e22053131a4f9f5a39079835c43bbbf8bd81bc6e93e040eee8b7cd263@0.0.0.0:20019", // [19]
	//"enode://d4b52d79185d91ea51888cccd3b8aff1cc0d2912344a852aa89d860b92677673a1e9a40398fd677b97ba467a330dfd6c6abf08fede15fe9d7f16aa26eaa4371a@0.0.0.0:20020", // [20]
	//"enode://497eaa555a86497b9e98b40ed63d3a4f7d18cc7c467c48889b8f1565e8a22a89c7171fc8f6230be9d383b01eae5ef3cfb0fe0f98f6a052e14b8f025141c70168@0.0.0.0:20021", // [21]

	// zrx
	"enode://59ca967b2c9c1442e81026f5ffc2b24f4b3787512194a41e4ab14dfac97e75b700988cac80f973641d40cd65f775f41955b93d2e843ebb03555b16dd9bf983d4@0.0.0.0:20022", // [22] a9b50794ab7a9987aa416c455c13aa6cc8c0448c501a3ce8e4840efe47cb5c29
	"enode://5c1feef1619789d0780bbb163b0ef5aa958421cb9be720f53d7061505fd74950544be2b6aab434f863ca177f678bd1add06f69fe372e2893758bda3d7f89ddb9@0.0.0.0:20023", // [23] 9d8996114eaa5bfe8274e0748180710090b8643fda52f628724909e5745dfaf8
	"enode://d4d87ffa05888559fc042e17248688bd7bb68bcdc66d893854e216d4c11d76af2c2a321bdff50c55107ba9b4d138e3a9c186313a71b9eac8fa8b2b449bccd9cb@0.0.0.0:20024", // [24] ceec6272073ee6e38674e13a3731a1191c45c1ddac62d8b9c5cd376dfe3e2dcb
	//"enode://1445264fdeaf296d4f2cf33a7467cbf2bc967d3b400d1cefeb68f1e2b789d7e200e98996010d4ac6b36578bb73d1d46f9d82619533534f6ebae618dd93fccf22@0.0.0.0:20025", // [25] 8978bc483cbdd116f9247a78fa9cd0c3914c0f48e3e5590471f0968e75c42d90
	//"enode://1c85a846b0e4b82032c48eafc8678afd14fc11cdbf6b7d11051c91257c789d67306fb49263eb851c278111a95a4a114fe2aabacbb51c6f72b8ccc0be68336ffa@0.0.0.0:20026", // [26] c299bddd794985c547c485cff697c4a38e4b36e44fd09cd7bdd8687bb0ae4d3c

	// lzw
	"enode://7504619a3cb827024abdfbd383b85c8e4ea3c053cb83ad998ca3d3bbe99b3052af794dd458311316e54affb7268d116d55adc84b85ffb44cc59310bdadb10fcf@0.0.0.0:20027", // [27] 7215e3db0f88916c800c00b850fadfeae1916739edeac61f1f3cbcfdeda96dac
	"enode://00dc5262bc8696a45b0dcd91fac78f65fea3eb8014bacc15a45070ea9a02a4399f004485446ec69645914aa5ea3ed5ddd84672f50723b50bef670924b38e6d9a@0.0.0.0:20028", // [28] c64b1ed47a260607d7e77a5bf1299c77735b57a787820edc71d70b042cfb6480
	"enode://b456a7f8e8abfb23d728ab22125e001abc4db2bb386f2adb8210c659e1688bb7e70b141c87fef5281b9cc202056c01a5b53b4d5f551283decb2d9e0a05b42e36@0.0.0.0:20029", // [29] fb13308263602dcfcac7cf473a24c0f9022fc913f0f72087eda2d940157a60b3
	//"enode://af6c1b5ab9d7b48de5a1ec3393319ab6d027501d993af1f184e54a292e7c22cc5a96a01b40e3ec15212a328c3d808928d61b8dfd537ac00675ecfd083d39037a@0.0.0.0:20030", // [30] 458f432d6b06b0cab1fe7120a7c306b0c7d845bed2368225f34475756e353b7a
	//"enode://7bf634cc46e8afe1935b7ea4db6f2750b2277cfe3319f8f42fb65ae7a6cfd7b900ad6552194eb292252590589b08b341a66caced55db2135686b73d73cf3d965@0.0.0.0:20031", // [31] 32e52e81b4b72d0eeb617bf5bc32ce2516f7f800bac1db75915449bb03a6fec7

	// wsp
	"enode://0415db831eda75733bd231b3b282dd312e706c378ff03c1a06590cc050cc01545bd45d80efe9fe2858b52bebba08e7210947341d8f4af27a04e4bc00428333fe@0.0.0.0:20032", // [32] 3ff92e66a95ec9295734d8b60055f70422befbfc79ba1c01252ac0b6e9533959
	"enode://7459d7858966a6aa8358c520b473c42d90858fc9656314d691f83d67f6190a1ac8575fb8faeaa80a2a44d077ae2b5eed733ee83897a3951f6f11b7de20c85470@0.0.0.0:20033", // [33] c244c81a619252c0943e4f3b0c13eec789fc643a02b7a49a40a25e2168fcede5
	"enode://4a88120d4949dc38d52c88409c952933eb30f53d999a5d53975cba3df15f195a61a4d45935854e4f6b11bfb04adbabd3f8b5bc1ca0bca38087b1120bd63a251c@0.0.0.0:20034", // [34] b2da617b98c9e02fbce3f6fc1e6b8681ddd6d9cb043f05faeea9f45244e80a85
	//"enode://f72a1e5a2541c60f60fa7f0bde3a8f76698418c197048e9dd9d11b0bd5c174b0a44774158a34b1ae7229edd85fd329b47037d327b7fb687ee68e48f1b0e9f424@0.0.0.0:20035", // [35] 3c996695ba8811378539466b888bc0c1721a821922a38e78766194efdec4f32a
	//"enode://2708d4c0ee42577149b29c89a7c083a76e0d0735a6002287afd8bd6e355bd9eda79012ecc8fff1f81c3893354fec566a6fbc5035ae3d832d27e24d0cd820091a@0.0.0.0:20036", // [36] 53e9946d5c0a69dce3e09cc43442c70cd041196ce27392e6274230b45bde032f

	//"enode://21d60ca2906000094a9c977d22211b76299fcdaa002970de668833d89876803c0022570edcaa0be8fc4a4ad56c87cfd6a1895cd26c3954d22485faced0488629@0.0.0.0:20037", // [37] 3d8702b07826e987fb2f3f99bee207173892806f18252e27dcf39dcd629aaed7
	//"enode://c3d14a3179c0ef22ac1d3f3f62d90917bf3a3c9260843c3912e0be4ad833e1c346b8e9cc16fac1057997780e1b37a4c6b995866cd0f8f76fd1a2908d4237a257@0.0.0.0:20038", // [38] 816a8e34e9fc17fd81b757175c3d696a4e18110edfe4b27474b8f12104844071
	//"enode://869ea6c7563ce19731adf80fb78a69080122c9f2104da7bbc9625a22f9d2ad2d50e98adbe1bdc6132a94ba1783d48fe09fe9412f3a54ccdbe1b0bb235da975a5@0.0.0.0:20039", // [39] 0c98f2fbf87092931892472641a1c1f38f34947e330712b0f4d44940e7744056
	//"enode://a77d91d4d653b30d3fa48d539da50510e05ffff06e3898193f1a5384a74e520f5b3a0d9f13dd0522dd39215254027261a316d3f70a6ea443dd03e79451c8c998@0.0.0.0:20040", // [40] 9dc5fc81fd352e7e65b3e8ed59d94c9f3f78a9b7ed82492812d33feecc0f6eab
	//"enode://0f107bb3ab390f353cfb583baaff72f2eaa8dba91e81e8fee69377cba2da290a8be50c27397ba2e30fcfbc2256319d43fccfaa3e05525d3e64ca2843f46e562a@0.0.0.0:20041", // [41] 1bd6a224803afaa1048962ccfcea02d4477d6bc2045a1d733decc1d6d7f312e0
	//"enode://faf9cec45c36c373445a24e5c7eb9f052dbd1032e61d26f3113a37680668f0f7ed5befebfce0de10a7fb4a6cf6627c6dc74b2b610976b4cdf6ddf900c2314e28@0.0.0.0:20042", // [42] 710b01ee744553bc9ac4feff703d1b05d42b0ac00ea97afdbdb03da69d7fc061
	//"enode://b0d9fa8e913c0e534608ae71fef2fd9fbb83085920b15f38d757bc57aa9994ffdaf70b31b0c61994809b9e635b20d5c809fa51903a6f02f63b141c993b51e59a@0.0.0.0:20043", // [43] f5f41a5ba97f8c3aa5a7668281e601aacdeafec2e4f97fa6fae4925f461c4b7b
	//"enode://6be6e32c897162fb32805d3304a6eba7c5188db593f768e820c17f9dad76b31e93e8ed4b00ef7d23fc52a53c1325ab4370519f8952e37f392116c9d5df07ae65@0.0.0.0:20044", // [44] 03311ba41516c7621bad3c32b06a09ec10050ca0f8ad8f724f3cf12292e16783
	//"enode://aa6f4f540e05a588ebeb5a5f20e56bd8bd814b2635764892bac9b89eceaf00c002f378a1a49aa310a416199a313a6eb2ab32e33e9f4e8c4387457fe280cd9357@0.0.0.0:20045", // [45] adca0ae414256f98e3fb5411ef677729bf8a4bb0fcf3d9723a303b0b5a2cf124
	//"enode://8c8af7b2efaea0ba06c99bacff9e3592b46487329d36f5995cf5fd074f928102763961f781952754430005b9df829217e1886e1d17396ca643582c77dc49ed09@0.0.0.0:20046", // [46] d39ac2e89926958edf4e434ffdd902b18e58fb9e1d9713c05fcd12f2f3febf6b
	//"enode://ad176a844cdbe6d72926562364b923e6f41e1c0ba0591a9f8775be0dbce692baaceaad4ce0c4747cb6706c9586ec2fe8a06350cfa08a14216b41fe6c0d6e59d7@0.0.0.0:20047", // [47] 10208710d565b8ce85e8742621b250cd822f25fef800cf4392f7f57d86c5fd65
	//"enode://75d3f93c5f5652dad2186e2a3fd09fbc54cb86a8fe7599e338fe9e5da7876bbe8ee460869713defea05c7277bfc415e9acff92e18c6e3cbbcfcb9632fe7040de@0.0.0.0:20048", // [48] 12f517b7a556085cd395ea26eeeedc36e4b8b656246d0e5f9a735903e9f2706f
	//"enode://8bba66edd006a8f7b377bdbb3c0c800e6c54342b4046745688b0e24a8c1a27d4027ac96dd254a3580ed6230563a55f9978986a6b276a8a221b093f3f062507c0@0.0.0.0:20049", // [49] 227d79fd9dd68820ddec2933f34019889722c2efe8ddb706c79762d08fcb1389
	//"enode://b18db6900055e578ecc1ef02a7793ad4311403f2a98c39c1914b50015c05c8afd11a12f0eb82eb952f0ccbe0ce508cfe2e052b1d39cce0d7b4d628eae2a128a8@0.0.0.0:20050", // [50] 76b684d514523308df7eb875241917916e9af64f0f4fdf91553b31f22bc55f83
}

var TestnetBootnodes = []string{
}

var TestnetMasternodes = []string{
}

// RinkebyBootnodes are the enode URLs of the P2P bootstrap nodes running on the
// Rinkeby test network.
var RinkebyBootnodes = []string{
}

// DiscoveryV5Bootnodes are the enode URLs of the P2P bootstrap nodes for the
// experimental RLPx v5 topic-discovery network.
var DiscoveryV5Bootnodes = []string{
}
