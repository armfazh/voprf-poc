package ecgroup

import (
	"crypto/elliptic"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/alxdavids/oprf-poc/go/oprf/utils"
	"github.com/cloudflare/circl/ecc/p384"
)

func TestHashToBaseP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{})
	err := performHashToBase(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSswuP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{})
	err := performSswu(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurveP384(t *testing.T) {
	curve := CreateNistCurve(p384.P384(), sha512.New(), utils.HKDFExtExp{})
	err := performHashToCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToBaseP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), utils.HKDFExtExp{})
	err := performHashToBase(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSswuP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), utils.HKDFExtExp{})
	err := performSswu(curve)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHashToCurveP521(t *testing.T) {
	curve := CreateNistCurve(elliptic.P521(), sha512.New(), utils.HKDFExtExp{})
	err := performHashToCurve(curve)
	if err != nil {
		t.Fatal(err)
	}
}

// performHashToBase performs full hash-to-base for each of the test inputs and
// checks against expected responses
func performHashToBase(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}
	for _, alpha := range testInputs {
		uArr, err := params.hashToBaseField([]byte(alpha), 0)
		if err != nil {
			return err
		}

		if len(uArr) != 1 {
			return errors.New("Only expecting one field element to be returned")
		}
		u := uArr[0]

		// check test vectors
		expected := expectedHashToBaseResponses[curve.Name()][alpha]
		cmp := u.Cmp(expected)
		if cmp != 0 {
			return errors.New(fmt.Sprintf("hash-to-base output for input alpha: %s is incorrect, expected: %s, got: %s", alpha, expected.String(), u.String()))
		}
	}
	return nil
}

// performSswu performs sswu for each of the test inputs and checks against
// expected responses
func performSswu(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}

	testVectors := expectedCurveEncodingResponses[curve.Name()]["sswu"]
	for _, alpha := range testInputs {
		vectors := testVectors[alpha]
		input := vectors["input"]
		Q, err := params.sswu([]*big.Int{input})
		if err != nil {
			return err
		}

		// check point is valid
		if !Q.IsValid() {
			return errors.New("Failed to generate a valid point")
		}

		// check test vectors
		chkQ := Point{X: vectors["x"], Y: vectors["y"], pog: curve, compress: true}
		if !Q.Equal(chkQ) {
			return errors.New("Points are not equal")
		}
	}
	return nil
}

// performHashToCurve performs full hash-to-curve for each of the test inputs
// and checks against expected responses
func performHashToCurve(curve GroupCurve) error {
	params, err := getH2CParams(curve)
	if err != nil {
		return err
	}
	for _, alpha := range testInputs {
		R, err := params.hashToCurve([]byte(alpha))
		if err != nil {
			return err
		}

		// check point is valid
		if !R.IsValid() {
			return errors.New("Failed to generate a valid point")
		}

		// check test vectors
		expected := expectedCurveEncodingResponses[curve.Name()]["full"][alpha]
		chkR := Point{X: expected["x"], Y: expected["y"], pog: curve, compress: true}
		if !R.Equal(chkR) {
			return errors.New("Points are not equal")
		}
	}
	return nil
}

// getBigIntFromDecString returns a bigint (without success value) from a decimal
// string
func getBigIntFromDecString(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("error creating big int")
	}
	return i
}

// test inputs and expected responses
//
// all expected responses are generated by running the poc at
// https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/ (commit:
// d6d786a150ca407e11f2b6e875d462801c139895) with DST=VOPRF-P384-SHA512-SSWU-RO-
// (replace P384 with P521 for curve P-521)
var (
	testInputs = []string{
		"",
		"1",
		"asdf",
		"test",
		"random",
	}

	expectedHashToBaseResponses = map[string](map[string]*big.Int){
		"P-384": map[string](*big.Int){
			"":       getBigIntFromDecString("15670280948239665018787050025088822552903093865230238970017602952833555416398748331082295637805213707088989441755988"),
			"1":      getBigIntFromDecString("1942715482632358166165565369095283869513634648389774012602448122359464835733690346035199729746417427046377204715303"),
			"asdf":   getBigIntFromDecString("24507112164256266255100924053603326775213507976390981967792131453083876194411216719447408537203841824718570787142464"),
			"test":   getBigIntFromDecString("6409376039185531560017287982748544597515854411296193693488280424481644496093326544690902528863962436268623496771541"),
			"random": getBigIntFromDecString("16247250678686872222869936093984092594492729196895879130498408114251281419554923530849483086336127849429159109128818"),
		},
		"P-521": map[string](*big.Int){
			"":       getBigIntFromDecString("4216039240707265220378657263021278020768422465068119601017201484646886479561518186937198936313849409370175543668175798296552919688504836207669266569365203558"),
			"1":      getBigIntFromDecString("6017657999201314031947466247648003537347124005478714362388027463511761061657526550991882932262191266129071052801005363210295657878808765181189788607749771742"),
			"asdf":   getBigIntFromDecString("4832501162858148399551282882241171101919257578198831035552760877439655601480467732536649190294070481194528342717955290831124139027938817608637169224179433084"),
			"test":   getBigIntFromDecString("1919944885504696148862885183140799390638420333626593005033343475947662814040903712780404634394785478702801717386942199598431493991053885235306974078423967206"),
			"random": getBigIntFromDecString("81724083395621300076858931720588541756830713667892350483191051685421534103577707316510562321164780605113178707672205371532153736293888775124101256370816076"),
		},
	}

	expectedCurveEncodingResponses = map[string](map[string](map[string](map[string]*big.Int))){
		"P-384": map[string](map[string](map[string]*big.Int)){
			"sswu": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"input": getBigIntFromDecString("15670280948239665018787050025088822552903093865230238970017602952833555416398748331082295637805213707088989441755988"),
					"x":     getBigIntFromDecString("15043091655123589139476535520316853145074562564067200072853707836963164937518115020044315814573473606362869394777187"),
					"y":     getBigIntFromDecString("33136250779564189967647894388148954739171786982148515795299597591669909884906353483262749333579115340263403769866626"),
				},
				"1": map[string]*big.Int{
					"input": getBigIntFromDecString("1942715482632358166165565369095283869513634648389774012602448122359464835733690346035199729746417427046377204715303"),
					"x":     getBigIntFromDecString("31712666608794813838450831245768352608061820731219254600083599907999316691595120493791689938289282078353090933837041"),
					"y":     getBigIntFromDecString("4206609551883326717841767788616124592725060605241985514692257065399455065867170452124896082541316335165985229730507"),
				},
				"asdf": map[string]*big.Int{
					"input": getBigIntFromDecString("24507112164256266255100924053603326775213507976390981967792131453083876194411216719447408537203841824718570787142464"),
					"x":     getBigIntFromDecString("293447988360561042611832928522597727479089496568847551940003813796772318506727270172476083341418873730785454701568"),
					"y":     getBigIntFromDecString("9761653435465566913614766398945376337690717880421211083207566458447975999387790669048364346983316135762944196549898"),
				},
				"test": map[string]*big.Int{
					"input": getBigIntFromDecString("6409376039185531560017287982748544597515854411296193693488280424481644496093326544690902528863962436268623496771541"),
					"x":     getBigIntFromDecString("31475109408547543147199457632396492796169708514999370150255421041761202109773477769740788427961884005032653705307760"),
					"y":     getBigIntFromDecString("33864641941997256225600777383976921381186308220482560482046046771370099718859942454304724377098962437161537347141181"),
				},
				"random": map[string]*big.Int{
					"input": getBigIntFromDecString("16247250678686872222869936093984092594492729196895879130498408114251281419554923530849483086336127849429159109128818"),
					"x":     getBigIntFromDecString("37310690097326955526874904412484957930185253899573931562503850700495595096900370544619577329930240463109907820476327"),
					"y":     getBigIntFromDecString("1835534565261005396339419959321852444925359938134835077886551094760311758797304939482177839199023849240736081211984"),
				},
			},
			"full": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"x": getBigIntFromDecString("30080611775067838193475075004665419527937570396653956651519246592569896222441582047156381322632437363661635355059005"),
					"y": getBigIntFromDecString("20783652428854690810060531204648743925284619218538801076205938644463325455616369725402399433833851021039801860251878"),
				},
				"1": map[string]*big.Int{
					"x": getBigIntFromDecString("29650639659274268559136011553864194418207682311050323428173462440594796529912091771908609365933993237437866304383610"),
					"y": getBigIntFromDecString("3123044785607009045040711490412599434775424958141229760770582294918664212503090438091817468980366885107838379509098"),
				},
				"asdf": map[string]*big.Int{
					"x": getBigIntFromDecString("29969588127226151911382588418021312873012227179044443716367955445066566752849478826037970129940763289625714821443011"),
					"y": getBigIntFromDecString("17410069451102133321720859095615324374699361853698493986383537650837194987993565478405818082113600644209841551176018"),
				},
				"test": map[string]*big.Int{
					"x": getBigIntFromDecString("35545509722549146939660727050796900115452941653073989167788838920390302482004128874997252970331147295344750824226579"),
					"y": getBigIntFromDecString("27687865874587861560504941570144773748765286782363087596575730017098117334752417380625066587341878521688930304472033"),
				},
				"random": map[string]*big.Int{
					"x": getBigIntFromDecString("21634107956511686237571364665733337762160319624271853087423499351943896659075117271938533968539011259822501269661449"),
					"y": getBigIntFromDecString("24988434919453800168740599843788684084233292688651079542544278337911292329783936136946570334754766549649989066107853"),
				},
			},
		},
		"P-521": map[string](map[string](map[string]*big.Int)){
			"sswu": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"input": getBigIntFromDecString("4216039240707265220378657263021278020768422465068119601017201484646886479561518186937198936313849409370175543668175798296552919688504836207669266569365203558"),
					"x":     getBigIntFromDecString("1583241003569918050467694998083898466688396764835413967647850966227277035160295177330295468547367794405276934143215905883531414881570476339782914632274132492"),
					"y":     getBigIntFromDecString("2261157005597413189666632438498210836537446935594357665751891890936966427396641813564724875718810280801568293799982776106267988720688833777023918521878826968"),
				},
				"1": map[string]*big.Int{
					"input": getBigIntFromDecString("6017657999201314031947466247648003537347124005478714362388027463511761061657526550991882932262191266129071052801005363210295657878808765181189788607749771742"),
					"x":     getBigIntFromDecString("3689006618282575909458304191444435728909928142514408413046894025031104395999370888793910558990623832528409842339865212043321822301182606534279995105692796146"),
					"y":     getBigIntFromDecString("3674130133016887008747566044570010878125279867237869356814642634013274555543269963380652205309082637184047406655160229891835492377963054723336921403957585790"),
				},
				"asdf": map[string]*big.Int{
					"input": getBigIntFromDecString("4832501162858148399551282882241171101919257578198831035552760877439655601480467732536649190294070481194528342717955290831124139027938817608637169224179433084"),
					"x":     getBigIntFromDecString("3587641712542424302363147595670418836647990115774886035642611061423464304750144295885164465481067853959313828334929652135283485669388438971011978002576334592"),
					"y":     getBigIntFromDecString("1166591553011498465748932011765295675532207809878300393497712796925679575382227419193250317797609644840311212185264807665661796062281032040925048338695465056"),
				},
				"test": map[string]*big.Int{
					"input": getBigIntFromDecString("1919944885504696148862885183140799390638420333626593005033343475947662814040903712780404634394785478702801717386942199598431493991053885235306974078423967206"),
					"x":     getBigIntFromDecString("2062253798483804829148243191456563587636899057332503847232875867098770373343453420808106408921964063122289152406789434362399421983342642248924879251585590262"),
					"y":     getBigIntFromDecString("2733305552040281958433176501221943780273450237846431380210345284275938776972529637766606377785009843987041327953659975900394939092414700637909550860575425158"),
				},
				"random": map[string]*big.Int{
					"input": getBigIntFromDecString("81724083395621300076858931720588541756830713667892350483191051685421534103577707316510562321164780605113178707672205371532153736293888775124101256370816076"),
					"x":     getBigIntFromDecString("438559262731670204098979042621092473977673543061116774481144159096924522993734594801492513859316134140164108744911658771418658951464068784358860544689226086"),
					"y":     getBigIntFromDecString("3096451370987141107699241935099153839221676236231005383287125482427299665553030251669652373331324072251854103411573093701673782606403348197823132113939024850"),
				},
			},
			"full": map[string](map[string]*big.Int){
				"": map[string]*big.Int{
					"x": getBigIntFromDecString("1680463792916462332632201500290428135621305324599010395788759982229637603188763979538614104414100864846293520110604703043114860415010045744967716224647707137"),
					"y": getBigIntFromDecString("1571215535651318779705535268404121071288377187475219478401284293627330807769549245308599929940293465106364248771721436902986288450687466345310240812208066443"),
				},
				"1": map[string]*big.Int{
					"x": getBigIntFromDecString("540646336378444038382267595524984766507583163447999920842259510670581526261787011475668719343175698473231150224546430036485765132973160491784324349560213268"),
					"y": getBigIntFromDecString("4317870999931378385925339391448871362478971168574725686745342453832463977332515324080585483104719015325536618393736489063674319757882048664617614412355550704"),
				},
				"asdf": map[string]*big.Int{
					"x": getBigIntFromDecString("1236570040291793246212611204463516456811257686517657419858406508382317240020113377970821957083125577934309716657096039765404008195307664869100751445274576268"),
					"y": getBigIntFromDecString("831087880384190323747330877248202768354739027506931908770359195710395809273574757615723393260008231352700744653128596959264161842152381221563554524747326996"),
				},
				"test": map[string]*big.Int{
					"x": getBigIntFromDecString("6537022532702563532612671297147654305764955165522345555356587110616569032261622158052250539397015229846438553143871554747013568573574200193985417185072337890"),
					"y": getBigIntFromDecString("5057023860813612754539839617519242092418485048636444012024741970720555676161511772488292285752658662129635234946840562677560078056607767464976322783704975840"),
				},
				"random": map[string]*big.Int{
					"x": getBigIntFromDecString("4922005435170794540903845092114591768943611167775895798506530408776904884990368831025118806316279025841874339185790647444979854275948055832750331061602273167"),
					"y": getBigIntFromDecString("3238285643820970602676416130611619056605213099037689753360128428024881669181236922366838989341556854610110234185713606895836411622905225772342198798537497089"),
				},
			},
		},
	}
)
