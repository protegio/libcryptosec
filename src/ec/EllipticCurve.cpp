#include <libcryptosec/ec/EllipticCurve.h>

const std::string EllipticCurve::notSpecified = "Not Specified";

EllipticCurve::EllipticCurve() {
	//Nothing to do
}

EllipticCurve::EllipticCurve(const ByteArray& encoded) {
	//TODO
}

EllipticCurve::EllipticCurve(const std::string& encoded) {
	//TODO
}

EllipticCurve::EllipticCurve(const EllipticCurve& c) :
		oid(c.oid), name(c.name),
		a(c.a), b(c.b), p(c.p), x(c.x), y(c.y),
		order(c.order), cofactor(c.cofactor)
{

}

EllipticCurve::EllipticCurve(EllipticCurve&& c) :
		oid(std::move(c.oid)), name(std::move(c.name)),
		a(std::move(c.a)), b(std::move(c.b)), p(std::move(c.p)), x(std::move(c.x)), y(std::move(c.y)),
		order(std::move(c.order)), cofactor(std::move(c.cofactor))
{

}

EllipticCurve::~EllipticCurve() {
}

EllipticCurve& EllipticCurve::operator=(const EllipticCurve& c) {
	if (&c == this) {
		return *this;
	}

	this->oid = c.oid;
	this->name = c.name;
	this->a = c.a;
	this->b = c.b;
	this->p = c.p;
	this->x = c.x;
	this->y = c.y;
	this->order = c.order;
	this->cofactor = c.cofactor;

	return *this;
}

EllipticCurve& EllipticCurve::operator=(EllipticCurve&& c) {
	if (&c == this) {
		return *this;
	}

	this->oid = std::move(c.oid);
	this->name = std::move(c.name);
	this->a = std::move(c.a);
	this->b = std::move(c.b);
	this->p = std::move(c.p);
	this->x = std::move(c.x);
	this->y = std::move(c.y);
	this->order = std::move(c.order);
	this->cofactor = std::move(c.cofactor);

	return *this;
}

const BIGNUM* EllipticCurve::BN_a() const {
	return this->a.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_b() const {
	return this->b.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_p() const {
	return this->p.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_x() const {
	return this->x.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_y() const {
	return this->y.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_order() const {
	return this->order.getBIGNUM();
}

const BIGNUM* EllipticCurve::BN_cofactor() const {
	return this->cofactor.getBIGNUM();
}

const BigInteger EllipticCurve::getA() const {
	return a;
}

void EllipticCurve::setA(const BigInteger& a) {
	this->a = a;
}

void EllipticCurve::setA(const std::string& hex) {
	this->a.setHexValue(hex);
}

void EllipticCurve::setA(const char* hex) {
	this->a.setHexValue(hex);
}

const BigInteger EllipticCurve::getB() const {
	return b;
}

void EllipticCurve::setB(const BigInteger& b) {
	this->b = b;
}


void EllipticCurve::setB(const std::string& hex) {
	this->b.setHexValue(hex);
}


void EllipticCurve::setB(const char* hex) {
	this->b.setHexValue(hex);
}

const BigInteger EllipticCurve::getCofactor() const {
	return cofactor;
}

void EllipticCurve::setCofactor(const BigInteger& cofactor) {
	this->cofactor = cofactor;
}

void EllipticCurve::setCofactor(const std::string& hex) {
	this->cofactor.setHexValue(hex);
}

void EllipticCurve::setCofactor(const char* hex) {
	this->cofactor.setHexValue(hex);
}

const std::string EllipticCurve::getName() const {
	return name;
}

void EllipticCurve::setName(const std::string& name) {
	this->name = name;
}

const std::string EllipticCurve::getOid() const {
	return oid;
}

void EllipticCurve::setOid(const std::string& oid) {
	this->oid = oid;
}

const BigInteger EllipticCurve::getOrder() const {
	return order;
}

void EllipticCurve::setOrder(const BigInteger& order) {
	this->order = order;
}


void EllipticCurve::setOrder(const std::string& hex) {
	this->order.setHexValue(hex);
}

void EllipticCurve::setOrder(const char* hex) {
	this->order.setHexValue(hex);
}

const BigInteger EllipticCurve::getP() const {
	return p;
}

void EllipticCurve::setP(const BigInteger& p) {
	this->p = p;
}

void EllipticCurve::setP(const std::string& hex) {
	this->p.setHexValue(hex);
}

void EllipticCurve::setP(const char* hex) {
	this->p.setHexValue(hex);
}

const BigInteger EllipticCurve::getX() const {
	return x;
}

void EllipticCurve::setX(const BigInteger& x) {
	this->x = x;
}

void EllipticCurve::setX(const std::string& hex) {
	this->x.setHexValue(hex);
}

void EllipticCurve::setX(const char* hex) {
	this->x.setHexValue(hex);
}

const BigInteger EllipticCurve::getY() const {
	return y;
}

void EllipticCurve::setY(const BigInteger& y) {
	this->y = y;
}

void EllipticCurve::setY(const std::string& hex) {
	this->y.setHexValue(hex);
}

void EllipticCurve::setY(const char* hex) {
	this->y.setHexValue(hex);
}
