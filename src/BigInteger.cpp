#include <libcryptosec/BigInteger.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/exception/BigIntegerException.h>

#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>

#include <time.h>
#include <stdlib.h>

BigInteger::BigInteger() :
		bigInt(BN_new())
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}

	BigInteger::setValue(0);
}

BigInteger::BigInteger(BIGNUM const* bn) :
		bigInt(BN_dup(bn))
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
	
}

BigInteger::BigInteger(long val) :
		bigInt(BN_new())

{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}

	BigInteger::setValue(val);
}

BigInteger::BigInteger(int val) :
		BigInteger((long) val)
{
}

BigInteger::BigInteger(const ASN1_INTEGER* val) :
		bigInt(BN_new())
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BIGNUM *rc = ASN1_INTEGER_to_BN(val, this->bigInt);
	if(!rc) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
}

BigInteger::BigInteger(const ByteArray& b) :
		bigInt(BN_new())
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BIGNUM *rc = BN_mpi2bn(b.getConstDataPointer(), b.getSize(), this->bigInt);
	if(!rc) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
}

BigInteger::BigInteger(const std::string& dec):
		bigInt(BN_new())
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
	
	BigInteger::setDecValue(dec);
}

BigInteger::BigInteger(const char* dec) :
		bigInt(BN_new())
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}

	BigInteger::setDecValue(dec);
}

BigInteger::BigInteger(const BigInteger& b) :
		bigInt(BN_dup(b.bigInt))
{
	if(this->bigInt == NULL) {
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::BigInteger");
	}
}

BigInteger::BigInteger(BigInteger&& b) :
		bigInt(std::move(b.bigInt))
{
	b.bigInt = nullptr;
}

BigInteger::~BigInteger()
{
	if (this->bigInt)
		BN_clear_free(this->bigInt);
}

BigInteger& BigInteger::operator=(long c)
{
	this->setValue(c);
	return *this;
}

BigInteger& BigInteger::operator=(const BigInteger& c)
{
	if (&c == this) {
		return *this;
	}

	BIGNUM *rc = BN_copy(this->bigInt, c.getBIGNUM());
	if(rc == NULL) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::operator=");
	}

	return *this;
}

BigInteger& BigInteger::operator=(BigInteger&& c)
{
	if (&c == this) {
		return *this;
	}

	this->bigInt = c.bigInt;
	c.bigInt = nullptr;

	return *this;
}

void BigInteger::setValue(const long val)
{
	unsigned long copy;
	
	if(val < 0)
	{
		copy = static_cast<unsigned long>(-val);
	}
	else
	{
		copy = static_cast<unsigned long>(val);
	}
	
	if(!(BN_set_word(this->bigInt, copy)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::BigInteger");
	}
	
	if(val < 0)
	{
		this->setNegative(true);
	}
}

void BigInteger::setNegative(const bool neg)
{
	if(neg)
	{
		BN_set_negative(this->bigInt, 1);
	}
	else
	{
		BN_set_negative(this->bigInt, 0);
	}
}

double BigInteger::getValue() const
{
	unsigned long tmp;
	double ret;
	
	tmp = BN_get_word(this->bigInt);
	if(tmp == ULONG_MAX)
	{
		throw BigIntegerException(BigIntegerException::UNSIGNED_LONG_OVERFLOW, "BigInteger::getValue");
	}
	
	ret = static_cast<double>(tmp);
	
	if(this->isNegative())
	{
		ret = -ret;
	}
	
	return ret;
}

ASN1_INTEGER* BigInteger::getASN1Value() const 
{
	ASN1_INTEGER* ret = NULL;
	
	if(!(ret = ASN1_INTEGER_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::getASN1Value");
	}
	
	if(!(BN_to_ASN1_INTEGER(this->bigInt, ret)))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::getASN1Value");
	}
	
	return ret;
}

ByteArray BigInteger::getBinValue() const
{
	int len = BN_bn2mpi(this->bigInt, NULL);

	/* consegue-se dignosticar algo retorno de BN_bn2mpi? pelo que olhei no codigo ele nunca retorna algo <= 0*/
	ByteArray ret(len);
	BN_bn2mpi(this->bigInt, ret.getDataPointer());

	return ret;
}

const BIGNUM * BigInteger::getBIGNUM() const
{
	return this->bigInt;
}

bool BigInteger::isNegative() const
{
	bool ret = false;
	
	if(BN_is_negative(this->bigInt))
	{
		ret = true;
	}
	
	return ret;
}

std::string BigInteger::toHex() const
{
	std::string ret;
	char* str; 
	
	str = BN_bn2hex(this->bigInt);
	ret = str; /*o conteudo do str eh copiado*/
	
	OPENSSL_free(str);
	return ret;
}

std::string BigInteger::toDec() const
{
	std::string ret;
	char* str; 
	
	str = BN_bn2dec(this->bigInt);
	ret = str; /*o conteudo do str eh copiado*/
	
	OPENSSL_free(str);
	return ret;
}

void BigInteger::setRandValue(int numBits)
{
	int top;
	int bottom;
	
	//semeia GNA
	srand(time(NULL));
	
	switch(rand() % 3)
	{
		case 0:
			top = -1;
			break;
		
		case 1:
			top = 0;
			break;
			
		case 2:
			top = 1;
			break;
	}
	
	switch (rand() % 2) {
		case 0:
			bottom = 0;
			break;
			
		case 1:
			bottom = 1;
			break;
	}
	
	if(!(BN_rand(this->bigInt, numBits, top, bottom)))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setRandValue");
	}
	
}

int BigInteger::size() const
{
	return BN_num_bits(this->bigInt);
}

void BigInteger::setHexValue(const std::string& hex)
{
	this->setHexValue(hex.c_str());
}

void BigInteger::setHexValue(const char* hex)
{
	if(!(BN_hex2bn(&this->bigInt, hex))) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setHexValue");
	}
}

void BigInteger::setDecValue(const std::string& dec)
{
	this->setDecValue(dec.c_str());
}

void BigInteger::setDecValue(const char* dec) {
	if(!(BN_dec2bn(&this->bigInt, dec))) {
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::setDecValue");
	}
}

BigInteger& BigInteger::add(const BigInteger& a)
{
	if(!(BN_add(this->bigInt, this->bigInt, a.getBIGNUM())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::add");
	}
	return *this;
}

BigInteger& BigInteger::add(long a)
{
	BigInteger b(a);
	return this->add(b);
}

BigInteger& BigInteger::sub(BigInteger const& a)
{
	if(!(BN_sub(this->bigInt, this->bigInt, a.getBIGNUM())))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::add");
	}
	return *this;
}

BigInteger& BigInteger::sub(long const a)
{
	BigInteger tmp(a);
	return this->sub(tmp);
}

BigInteger& BigInteger::mul(BigInteger const& a)
{
	BN_CTX* ctx = NULL;
	BIGNUM* r = NULL;
	
	if(!(r = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mul");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mul");
	}
	
	if(!BN_mul(r, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mul");
	}
	
	if(BN_copy(this->bigInt, r) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mul");
	}
	
	BN_free(r);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::mul(long const a)
{
	BigInteger tmp(a);
	return this->mul(tmp);
}

BigInteger BigInteger::operator*(BigInteger const& a) const
{
	BigInteger tmp(*this);
	return tmp.mul(a);
}

BigInteger BigInteger::operator*(long c) const
{
	BigInteger tmp1(*this);
	BigInteger tmp2(c);
	return tmp1.mul(tmp2);
}

BigInteger& BigInteger::div(BigInteger const& a)
{
	BN_CTX* ctx = NULL;
	BIGNUM* dv = NULL;
	BIGNUM* rem = NULL;
	
	if(a == 0)
	{
		throw BigIntegerException(BigIntegerException::DIVISION_BY_ZERO, "BigInteger::div");
	}
	
	if(!(dv = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!(rem = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::div");
	}
	
	if(!BN_div(dv, rem, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::div");
	}
	
	if(BN_copy(this->bigInt, dv) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::div");
	}
	
	BN_free(dv);
	BN_free(rem);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::div(long const a)
{
	BigInteger tmp(a);
	return this->div(tmp);
}

BigInteger BigInteger::operator/(BigInteger const& a) const
{
	BigInteger tmp(*this);
	return tmp.div(a);
}

BigInteger BigInteger::operator/(long c) const
{
	BigInteger a(*this);
	BigInteger b(c);
	
	return a.div(b);
}

BigInteger& BigInteger::mod(BigInteger const& a)
{
	BN_CTX* ctx = NULL;
	BIGNUM* rem = NULL;
	
	if(a == 0)
	{
		throw BigIntegerException(BigIntegerException::DIVISION_BY_ZERO, "BigInteger::mod");
	}
	
	if(!(rem = BN_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mod");
	}
	
	if(!(ctx = BN_CTX_new()))
	{
		throw BigIntegerException(BigIntegerException::MEMORY_ALLOC, "BigInteger::mod");
	}
	
	if(!BN_mod(rem, this->bigInt, a.getBIGNUM(), ctx))
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mod");
	}
	
	if(BN_copy(this->bigInt, rem) == NULL)
	{
		throw BigIntegerException(BigIntegerException::INTERNAL_ERROR, "BigInteger::mod");
	}
	
	BN_free(rem);
	BN_CTX_free(ctx);
	return (*this);
}

BigInteger& BigInteger::mod(long const a)
{
	BigInteger tmp(a);
	return this->mod(tmp);
}

BigInteger BigInteger::operator%(BigInteger const& a) const
{
	BigInteger tmp(*this);
	return tmp.mod(a);
}

BigInteger BigInteger::operator%(long c) const
{
	BigInteger tmp(*this);
	return tmp.mod(c);
}

int BigInteger::compare(BigInteger const& a) const
{
	return BN_cmp(this->getBIGNUM(), a.getBIGNUM());
}

BigInteger BigInteger::operator+(const BigInteger& c) const
{
	BigInteger ret;
	ret.add(*this);
	return ret.add(c);
}

BigInteger BigInteger::operator+(long c) const
{
	BigInteger ret;
	ret.add(*this);
	return ret.add(c);
}

BigInteger& BigInteger::operator+=(const BigInteger& c)
{
	return this->add(c);
}

BigInteger& BigInteger::operator+=(long c)
{
	BigInteger tmp(c);
	return this->add(tmp);
}

BigInteger BigInteger::operator-(const BigInteger& c) const
{
	BigInteger ret;
	ret.add(*this);
	return ret.sub(c);
}

BigInteger BigInteger::operator-(long c) const
{
	BigInteger ret;
	ret.add(*this);
	return ret.sub(c);
}

bool BigInteger::operator==(const BigInteger& c) const
{
	return this->compare(c) == 0;
}

bool BigInteger::operator==(long c) const
{
	BigInteger tmp(c);
	return this->compare(tmp) == 0;
}

bool BigInteger::operator!=(const BigInteger& c) const
{
	return this->compare(c) != 0;
}

bool BigInteger::operator!=(long c) const
{
	BigInteger tmp(c);
	return this->compare(tmp) != 0;
}

bool BigInteger::operator>(const BigInteger& c) const
{
	return this->compare(c) == 1;
}

bool BigInteger::operator>(long c) const
{
	BigInteger tmp(c);
	return this->compare(tmp) == 1;
}

bool BigInteger::operator>=(const BigInteger& c) const
{
	return (this->compare(c) >= 0);
}

bool BigInteger::operator>=(long c) const
{
	BigInteger tmp(c);
	return (*this >= tmp);
}

bool BigInteger::operator<(const BigInteger& c) const
{
	return this->compare(c) == -1;
}

bool BigInteger::operator<(long c) const
{
	BigInteger tmp(c);
	return this->compare(tmp) == -1;
}

bool BigInteger::operator<=(const BigInteger& c) const
{
	return (this->compare(c) <= 0);
}

bool BigInteger::operator<=(long c) const
{
	BigInteger tmp(c);
	return (*this <= tmp);
}

bool BigInteger::operator!() const
{
	return ((*this) == 0);
}

bool BigInteger::operator||(const BigInteger& c) const
{
	bool a = !((*this) == 0);
	bool b = !(c == 0);
	
	return a || b;
}

bool BigInteger::operator||(long c) const
{
	bool a = !((*this) == 0);
	bool b = c != 0;
	
	return a || b;
}

bool BigInteger::operator&&(const BigInteger& c) const
{
	bool a = !((*this) == 0);
	bool b = !(c == 0);
	
	return a && b;
}

bool BigInteger::operator&&(long c) const
{
	bool a = !((*this) == 0);
	bool b = c != 0;
	
	return a && b;
}

BigInteger operator+(long c, const BigInteger& d)
{
	return d + c;
}

BigInteger operator-(long c, const BigInteger& d)
{
	BigInteger tmp(c);
	return tmp - d;
}
