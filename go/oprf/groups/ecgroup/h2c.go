package ecgroup

import (
	"fmt"
	"hash"
	"math/big"

	"github.com/alxdavids/oprf-poc/go/oerr"
	oc "github.com/alxdavids/oprf-poc/go/oprf/oprfCrypto"
)

// h2cParams contains all of the parameters required for computing the
// hash_to_curve mapping algorithm, see
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05 for more
// information.
type h2cParams struct {
	gc      GroupCurve
	name    string
	dst     []byte
	mapping int
	z       int
	a       *big.Int
	b       *big.Int
	p       *big.Int
	m       int
	hash    hash.Hash
	ee      oc.ExtractorExpander
	l       int
	hEff    *big.Int
	isSqExp *big.Int
	sqrtExp *big.Int
	sgn0    func(*big.Int) *big.Int
}

// getH2CParams returns the h2cParams object for the specified curve
func getH2CParams(gc GroupCurve) (h2cParams, oerr.Error) {
	h2cName := "SSWU-RO"
	switch gc.Name() {
	case "P-384":
		return h2cParams{
			gc:      gc,
			name:    h2cName,
			dst:     []byte(fmt.Sprintf("VOPRF-P384-SHA512-%s-", h2cName)),
			mapping: 0,
			z:       -12,
			a:       gc.consts.a,
			b:       gc.ops.Params().B,
			p:       gc.P(),
			m:       1,
			hash:    gc.Hash(),
			ee:      gc.ee,
			l:       72,
			hEff:    one,
			isSqExp: gc.consts.isSqExp,
			sqrtExp: gc.consts.sqrtExp,
			sgn0:    gc.sgn0,
		}, oerr.Error{}
	case "P-521":
		return h2cParams{
			gc:      gc,
			name:    h2cName,
			dst:     []byte(fmt.Sprintf("VOPRF-P521-SHA512-%s-", h2cName)),
			mapping: 0,
			z:       -4,
			a:       gc.consts.a,
			b:       gc.ops.Params().B,
			p:       gc.P(),
			m:       1,
			hash:    gc.Hash(),
			ee:      gc.ee,
			l:       96,
			hEff:    one,
			isSqExp: gc.consts.isSqExp,
			sqrtExp: gc.consts.sqrtExp,
			sgn0:    gc.sgn0,
		}, oerr.Error{}
	}
	return h2cParams{}, oerr.ErrUnsupportedGroup
}

// hashToBase hashes a buffer into a vector of underlying base field elements,
// where the base field is chosen depending on the associated elliptic curve
func (params h2cParams) hashToBaseField(buf []byte, ctr int) ([]*big.Int, oerr.Error) {
	os, err := i2osp(0, 1)
	if err.Err() != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	hashFunc := func() hash.Hash {
		hash := params.hash
		hash.Reset()
		return hash
	}
	extractor := params.ee.Extractor()
	msgPrime := extractor(hashFunc, append(buf, os...), params.dst)
	osCtr, err := i2osp(ctr, 1)
	if err.Err() != nil {
		return nil, oerr.ErrInternalInstantiation
	}
	infoPfx := append([]byte("H2C"), osCtr...)
	i := 1
	res := make([]*big.Int, params.m)
	expander := params.ee.Expander()
	for i <= params.m {
		osi, err := i2osp(i, 1)
		if err.Err() != nil {
			return nil, oerr.ErrInternalInstantiation
		}
		info := append(infoPfx, osi...)
		reader := expander(hashFunc, msgPrime, info)
		t := make([]byte, params.l)
		reader.Read(t)
		ei := os2ip(t)
		res[i-1] = new(big.Int).Mod(ei, params.p)
		i++
	}
	return res, oerr.Error{}
}

// hashToCurve hashes a buffer to a curve point on the chosen curve, this
// function can be modelled as a random oracle.
func (params h2cParams) hashToCurve(alpha []byte) (Point, oerr.Error) {
	u0, err := params.hashToBaseField(alpha, 0)
	if err.Err() != nil {
		return Point{}, err
	}
	u1, err := params.hashToBaseField(alpha, 1)
	if err.Err() != nil {
		return Point{}, err
	}

	// attempt to encode bytes as curve point
	Q0 := Point{}.New(params.gc).(Point)
	Q1 := Point{}.New(params.gc).(Point)
	var e0, e1 oerr.Error
	switch params.gc.Name() {
	case "P-384", "P-521":
		Q0, e0 = params.sswu(u0)
		Q1, e1 = params.sswu(u1)
		break
	default:
		e0 = oerr.ErrIncompatibleGroupParams
	}

	// return oerr.Error if one occurred, or the point that was encoded
	if e0.Err() != nil {
		return Point{}, e0
	} else if e1.Err() != nil {
		return Point{}, e1
	}

	// construct the output point R
	R, err := Q0.Add(Q1)
	if err.Err() != nil {
		return Point{}, err
	}
	P, err := R.(Point).clearCofactor(params.hEff)
	if err.Err() != nil {
		return Point{}, err
	}
	return P, oerr.Error{}
}

// sswu completes the Simplified SWU method curve mapping defined in
// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2
func (params h2cParams) sswu(uArr []*big.Int) (Point, oerr.Error) {
	if len(uArr) > 1 {
		return Point{}, oerr.ErrIncompatibleGroupParams
	}
	u := uArr[0]
	p, A, B, Z := params.p, params.a, params.b, big.NewInt(int64(params.z))

	// consts
	// c1 := -B/A, c2 := -1/Z
	c1 := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(B, minusOne), new(big.Int).ModInverse(A, p)), p)
	c2 := new(big.Int).Mul(minusOne, new(big.Int).ModInverse(Z, p))

	// steps
	t1 := new(big.Int).Mul(Z, new(big.Int).Exp(u, two, p))   // 1.     t1 = Z * u^2
	t2 := new(big.Int).Exp(t1, two, p)                       // 2.     t2 = t1^2
	x1 := new(big.Int).Add(t1, t2)                           // 3.     x1 = t1 + t2
	x1 = inv0(x1, p)                                         // 4.     x1 = inv0(x1)
	e1 := revCmpBit(new(big.Int).Abs(cmpToBigInt(x1, zero))) // 5.     e1 = x1 == 0
	x1 = x1.Add(x1, one)                                     // 6.     x1 = x1 + 1
	x1 = cmov(x1, c2, e1)                                    // 7.     x1 = CMOV(x1, c2, e1)
	x1 = x1.Mul(x1, c1)                                      // 8.     x1 = x1 * c1
	gx1 := new(big.Int).Exp(x1, two, p)                      // 9.    gx1 = x1^2
	gx1 = gx1.Add(gx1, A)                                    // 10.   gx1 = gx1 + A
	gx1 = gx1.Mul(gx1, x1)                                   // 11.   gx1 = gx1 * x1
	gx1 = gx1.Add(gx1, B)                                    // 12.   gx1 = gx1 + B
	x2 := new(big.Int).Mul(t1, x1)                           // 13.    x2 = t1 * x1
	t2 = t2.Mul(t1, t2)                                      // 14.    t2 = t1 * t2
	gx2 := new(big.Int).Mul(gx1, t2)                         // 15.   gx2 = gx1 * t2
	e2 := isSquare(gx1, params.isSqExp, p)                   // 16.    e2 = is_square(gx1)
	x := cmov(x2, x1, e2)                                    // 17.     x = CMOV(x2, x1, e2)
	y2 := cmov(gx2, gx1, e2)                                 // 18.    y2 = CMOV(gx2, gx1, e2)
	y := sqrt(y2, params.sqrtExp, p)                         // 19.     y = sqrt(y2)
	e3 := sgnCmp(u, y, params.sgn0)                          // 20.    e3 = sgn0(u) == sgn0(y)
	y = cmov(new(big.Int).Mul(y, minusOne), y, e3)           // 21.     y = CMOV(-y, y, e3)

	// construct point and assert that it is correct
	P := Point{}.New(params.gc).(Point)
	P.X = x.Mod(x, p)
	P.Y = y.Mod(y, p)
	if !P.IsValid() {
		return Point{}, oerr.ErrInvalidGroupElement
	}
	return P, oerr.Error{}
}

// cmpToBigInt converts the return value from a comparison operation into a
// *big.Int
func cmpToBigInt(a, b *big.Int) *big.Int {
	return big.NewInt(int64(a.Cmp(b)))
}

// equalsToBigInt returns big.Int(1) if a == b and big.Int(0) otherwise
func equalsToBigInt(a, b *big.Int) *big.Int {
	cmp := cmpToBigInt(a, b)
	equalsRev := new(big.Int).Abs(cmp)
	return revCmpBit(equalsRev)
}

// sqrt computes the sqrt of x mod p (pass in exp explicitly so that we don't
// have to recompute)
func sqrt(x, exp, p *big.Int) *big.Int {
	x = x.Mod(x, p)
	y := new(big.Int).Exp(x, exp, p)
	return y
}

// isSquare returns 1 if x is a square integer in FF_p and 0 otherwise, passes
// in the value exp to compute the square root in the exponent
func isSquare(x, exp, p *big.Int) *big.Int {
	b := new(big.Int).Exp(x, exp, p)
	c := b.Cmp(one)
	d := b.Cmp(zero)
	e := int64(c * d)
	return equalsToBigInt(big.NewInt(e), zero) // returns 1 if square, and 0 otherwise
}

// revCmp reverses the result of a comparison bit indicator
func revCmpBit(cmp *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(cmp, one), two)
}

// inv0 returns the inverse of x in FF_p, also returning 0^{-1} => 0
func inv0(x, p *big.Int) *big.Int {
	return x.Exp(x, new(big.Int).Sub(p, two), p)
}

// i2osp converts an integer to an octet-string
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func i2osp(x, xLen int) ([]byte, oerr.Error) {
	if x < 0 || x >= (1<<(8*xLen)) {
		return nil, oerr.ErrInternalInstantiation
	}
	ret := make([]byte, xLen)
	val := x
	for i := xLen - 1; i >= 0; i-- {
		ret[i] = byte(val & 0xff)
		val = val >> 8
	}
	return ret, oerr.Error{}
}

// os2ip converts an octet-string to an integer
// (https://tools.ietf.org/html/rfc8017#section-4.1)
func os2ip(x []byte) *big.Int {
	return new(big.Int).SetBytes(x)
}
