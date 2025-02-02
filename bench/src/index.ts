import { validateAddress as currentValidateAddress } from "../../js/"
import { validateAddress } from "@mradomski/tinyerc55"
import { utils } from 'ethers'

(async () => {
    const addresses: string[] = [
        "0x7F2245BCA3336Af839Bf7378ed872ED92651B6a3",
        "0xb36c05b9b5b183930E39E3bA4E0Ef00dA2113075",
        "0xf1ab8Aa2e09a876ec0b22911EEc9B755d0db4060",
        "0xF87ED7De5173051aDC11D568e06B9322D02e6A88",
        "0x2b93782F00515b0CfC9ed2f099dF53a8e2F4ADc4",
        "0x0C3E88890398EBa5333Bc6d53769a77569BE66D4",
        "0xCC824eD38366828015821224eFB7db7c87686712",
        "0x88E8d476ca5c838C10A15eB9283D18aa49b122db",
        "0xBC7081049A67BFa7d840AB8f3ed5A5E076cfAB8C",
        "0xDd6Df98385b088572138dC5B75a955e8C711a15F",
        "0x1da8e74e5aeDF3F771bcFc731A2246588FB9F6C3",
        "0xF47959b608183D0Bf95F49Fe18EBD5a347B4Ce0B",
        "0xE56C0C06333C4b88EDE68e110D87d1CbDA283fbf",
        "0xdBaFfd043025474dcC3fEB3253B070349E950574",
        "0x49305543dd4a71EE7631eFa2294E87a98E29400a",
        "0xf77B3246A9E338B65674aF608e127047a3D570cd",
        "0x2Edad4f0F38F7A54a7E80a52e2Dc7bd7ffa9F281",
        "0x2AEdEaDE5eef261b5B21C53a38353D02C2455894",
        "0xFA54675665C2FD963f840487CBfFD9826BcC4aB7",
        "0x98F09d6b59A36DB814447786b3d3e7Ac4a879483",
        "0x045F7bDDb1e8150314A30e90fF2cCdeA46369CcA",
        "0x0Cd5Ab6Ec75b267F35Ee95b8134f95beA9c3565b",
        "0xFA0e47B16832Daf65b0562A90867dAF64B328021",
        "0xd48BF1eF8F7593D9333461B8d33b7b2674CC8430",
        "0x6C38E1Ea1c2f6253E6Cd611026b08f090fDACA61",
        "0xCB96fc96403BB68f70595336288d970f67952545",
        "0x36B1D6803e3e14947ef7514e9F8632598a7078dd",
        "0x5445920a0A481b83f676afF426CEbd7E43bfadeE",
        "0x0068907ba65DeC867E8278935b4eD8e690889b04",
        "0xc26ae8f149dD3cBA139fbce5bc89ec690A757bae",
        "0x31a773C536F559288BbD7AbdabCd807C12178501",
        "0x0ef504d5c629eeFeD6DAa6454D2FFCF68BF50A0b",
        "0xA221f8c892d9F33BF03baA4c6e829bDcA9976482",
        "0x45857308187e488F4bDbdA54B1653D2042D6762f",
        "0x6D2234d28Ac4a08B50cD8F472654f24337596dD9",
        "0x17B68581Ba411BBf386C8f19992FabF97E4824Fd",
        "0xF4b5C115f5315eEA2214f24164BBA1c0E88FC009",
        "0x52A7eC86B1CB3f3d3483780334e17F1a93Ca2611",
        "0x114ddd107B38629110Fed76a0eC0C7A34353717D",
        "0x22FA3ce3e262d8F68353f0568113c21593CBA835",
        "0xeD82caCC9C86328eBE0Ea1dc21CCbbF1a4bfFdaB",
        "0x5d89155e5e1084b77c628cE87C3bF94262A98CdF",
        "0x438045456888fd29cc5a7e11d29455163B78da84",
        "0x6A58155059FC77796B2c0cb51d61c3cC51938fFE",
        "0x22afC36B0114e61A52ac54d440992cA032faC891",
        "0x3197A76149E67fd9b4eae3B9c79aA16A08BEDED4",
        "0xb08542AdbcBc517D6AfAE5101d8FBEF358BC5c23",
        "0x4C2247dd93b2b08697a73a25Ca75Ee011a5d4Ff0",
        "0x5DabBCCef4CbC4271806CFb83982AEd314926Ab0",
        "0x2a96BB96581371602a5F97478Bceb670d158a821",
        "0xAE416AeD28Fd4587D84B6447c65E55DB1a7B6911",
        "0x3025A42C68f08ab67913831E9D9a94F2adC57527",
        "0x9ade3E7703b81a642A69815F52dE9168267c600C",
        "0x8bf7B38E0142F17f769E7dE2FCdF41245F5D3b0C",
        "0xaff611177E7E815a85487776C0055339C82952d5",
        "0xfA580250c1f34405d66756da700b70C4de9eDd4f",
        "0x21DBA839747f3Efc2100D9628d31F25B032910dA",
        "0x20ac8beE7ebc997A319369cD70d728509d91A50E",
        "0x47dd814E84E759082935B550eb266c7b0c8ab7C0",
        "0xFB4f04e94229dd7CEA7ca19857711b1c90E1d85a",
        "0xB6D2659Bea6D311b3771842A0c27eBBc1d2A96dC",
        "0xc3ee1aef813FF3544D4A4FE71cC5D6ae4392031b",
        "0x1d65013539Dd61f6A8f04cC4d6A5ec527b0A1501",
        "0xC5612Fb62C6fF952831B4975EaCa0780b171D8dd",
        "0x73b8328b2421cfD719cD5395b7a3e5f611253071",
        "0x2bA35B73DE19972BEfb4b5f95f4F251DF5dc8Ff4",
        "0xfC99f65B7DDe603418e7A4bdf02b5CDaB694dBb3",
        "0x7be060e056C302757772186a1D67Ef61A38984a4",
        "0xB0213e0D8118Bb98871432ed49B5bb374F60330c",
        "0x3109E926c6A0ba156aAdc1CA6c339EaEd031e4Cf",
        "0xc7591fAcb196FD8f3e88Ac94458D12681E2aa484",
        "0xfAb0F46ccb45c507a91095FA8d866C94fB401F28",
        "0xE352AA500455cb6EC6A65418922d37872bd0CBF6",
        "0x36D066f3246cB8BE558b4A730f57f4889ec60c5C",
        "0xd375C3b8b9262Aef4B0743b8aC81AA9fabc3f5de",
        "0x698f28adfF4a2cF3812942B271712eD918cBfb8c",
        "0x81e57aFfDD704BF2B757fdEd67C027A7E00c33BB",
        "0x64D2cED8B0d0F441AFe933699E40150130E5653b",
        "0xCE2A82811552F6EC002774CB1b564943c3e4E4b2",
        "0xC8Cb83E01F28af90bA77A6d8EBBaC722e2a009ec",
        "0x7c3f990846C87b16Faf00d570E1A206E9d02fE13",
        "0x17F69794E8CBED29f7C5d0CB1C3Fa2901A0974b0",
        "0xE7E3a09619220c27Be681a50d49b1b9d98456531",
        "0x47F131018184a883D110532566978D24327E8867",
        "0x55795A4dC0725cA8058bB756aE43340EAd3Bb8fD",
        "0xE1fa61110e025672568eDfb14ABFA610cFeE7B42",
        "0xdCcd338985ABA90D7C1dB187eb16Be79ED8A49d0",
        "0x8fe64589947ffa942755c6C300Dc852dfA6FD58c",
        "0xD63ED2B5a75B3B995740d32128Ddb4f8D5420374",
        "0x322cC2f30c9885DA25c0fb00f330bcb6508a458b",
        "0x6b47c8706Cbb4De365638888790Ac1e367FB87B8",
        "0x3a95045256e29b449D5798fA8c10cDe10C7e73c5",
        "0xAA9e1aB9E160ed36788342f1109538cE5235EDA2",
        "0xA5ac242F7942dbE5a39Da65C5f6107AC42D1B5ca",
        "0x1dcC5eaAed8a925A90a5a20eC80fF04D70957983",
        "0xcff904246B2a2247d1b018aa5056C93aB655068a",
        "0x984239A54c761999d57437A7Fec54f3cB56a4BC6",
        "0x8515147E8fCddD191566879eC0de309a470355ac",
        "0x9907e9c0e8145Ca30f3Cd54bfE28b90DE9c027A6",
        "0xDF58f857326472a659B3D975f342DF315b74Db98"
    ]

	const { run, bench, boxplot, summary } = await import("mitata");

	boxplot(() => {
		summary(() => {
			bench("single ethers", () => utils.getAddress("0xf4Ceb9ABaa73C587ec77d0A978210F6A614bED36"));
			bench("single release", () => validateAddress("0xf4Ceb9ABaa73C587ec77d0A978210F6A614bED36"));
			bench("single current", () => currentValidateAddress("0xf4Ceb9ABaa73C587ec77d0A978210F6A614bED36"));
		});

		summary(() => {
			bench("100 ethers", () => {
                for(const address of addresses) {
                    utils.getAddress(address)
                }
            });
			bench("100 release", () => {
                for(const address of addresses) {
                    validateAddress(address)
                }
            });
			bench("100 current", () => {
                for(const address of addresses) {
                    currentValidateAddress(address)
                }
            });
		});
	});

	run().catch();
})();
