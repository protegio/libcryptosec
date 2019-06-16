#include <libcryptosec/BigInteger.h>

#include <libcryptosec/ByteArray.h>
#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/EncodeException.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/NullPointerException.h>

#include <openssl/asn1t.h>
#include <openssl/ossl_typ.h>

#include <time.h>
#include <stdlib.h>
#include <cmath>

#define THROW_BIG_INTEGER_ERROR_IF(exp) THROW_IF(exp, BigIntegerException, BigIntegerException::MEMORY_ALLOC)

BigInteger::BigInteger() :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	this->setInt64(0);
}

BigInteger::BigInteger(const BIGNUM* bn) :
		bigInt(BN_dup(bn))
{
	THROW_NULL_POINTER_IF(bn == NULL);
	THROW_DECODE_IF(this->bigInt == NULL);
}

BigInteger::BigInteger(int64_t value) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	this->setInt64(value);
}

BigInteger::BigInteger(uint64_t value) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	this->setUint64(value);
}

BigInteger::BigInteger(int32_t value) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	int64_t value64 = static_cast<int64_t>(value);
	value64 = value64 << 32;
	value64 = value64 >> 32;
	this->setInt64(value64);
}

BigInteger::BigInteger(uint32_t value) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	int64_t value64 = static_cast<int64_t>(value);
	value64 = value64 << 32;
	value64 = value64 >> 32;
	this->setUint64(value64);
}

BigInteger::BigInteger(const ASN1_INTEGER* val) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);
	THROW_NULL_POINTER_IF(val == NULL);

	BIGNUM *bn = ASN1_INTEGER_to_BN(val, this->bigInt);
	THROW_DECODE_IF(bn == NULL);
}

BigInteger::BigInteger(const ByteArray& b) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);

	const unsigned char *dataPointer = b.getConstDataPointer();
	unsigned int dataSize = b.getSize();

	// TODO: porque usavamos o formato mpi e não bin?
	// BIGNUM *bn = BN_mpi2bn(dataPointer, dataSize, this->bigInt);

	BIGNUM *bn = BN_bin2bn(dataPointer, dataSize, this->bigInt);
	THROW_DECODE_IF(bn == NULL);
}

BigInteger::BigInteger(const std::string& value, uint32_t base) :
		bigInt(BN_new())
{
	THROW_BAD_ALLOC_IF(this->bigInt == NULL);

	if (base == 10) {
		this->setDecValue(value);
	} else if (base == 16) {
		this->setHexValue(value);
	} else {
		THROW_DECODE_ERROR_IF(true);
	}
}

BigInteger::BigInteger(const char* value, uint32_t base) :
		BigInteger(std::string(value), base)
{
}

BigInteger::BigInteger(const BigInteger& b) :
		bigInt(BN_dup(b.bigInt))
{
	THROW_DECODE_IF(this->bigInt == NULL);
}

BigInteger::BigInteger(BigInteger&& b) :
		bigInt(std::move(b.bigInt))
{
	b.bigInt = nullptr;
}

BigInteger::~BigInteger()
{
	if (this->bigInt != NULL) {
		BN_clear_free(this->bigInt);
	}
}

BigInteger& BigInteger::operator=(const BigInteger& c)
{
	if (&c == this) {
		return *this;
	}

	BIGNUM *bn = BN_copy(this->bigInt, c.bigInt);
	THROW_DECODE_IF(bn == NULL);

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

void BigInteger::setInt64(int64_t value)
{
	uint64_t value64 = abs(value);

	int rc = BN_set_word(this->bigInt, value64);
	THROW_DECODE_IF(rc == 0);

	this->setNegative(value < 0);
}

void BigInteger::setUint64(uint64_t value)
{
	int64_t copy = value;

	int rc = BN_set_word(this->bigInt, copy);
	THROW_DECODE_IF(rc == 0);
}

void BigInteger::setNegative(bool neg) noexcept
{
	int negativeFlag = (neg ? 1 : 0);
	BN_set_negative(this->bigInt, negativeFlag);
}

int64_t BigInteger::toInt64() const
{
	unsigned long ret = BN_get_word(this->bigInt);
	THROW_OVERFLOW_IF(ret == ULONG_MAX);

	// CAST: implicit
	return ret;
}

int32_t BigInteger::toInt32() const
{
	int64_t value = this->toInt64();
	THROW_OVERFLOW_IF(value > INT32_MAX || value < INT32_MIN);
	return value;
}

ASN1_INTEGER* BigInteger::toAsn1Integer() const
{
	ASN1_INTEGER* ret = ASN1_INTEGER_new();
	THROW_BAD_ALLOC_IF(ret == NULL);

	ret = BN_to_ASN1_INTEGER(this->bigInt, ret);
	THROW_ENCODE_IF(ret == NULL);

	return ret;
}

ByteArray BigInteger::toByteArray() const
{
	// TODO: porque usavamos mpi e não bin?
	int size = BN_num_bytes(this->bigInt);
	THROW_ENCODE_IF(size <= 0);

	ByteArray ret(size);
	// TODO: porque usavamos mpi e não bin?
	size = BN_bn2bin(this->bigInt, ret.getDataPointer());
	THROW_ENCODE_IF(size <= 0);

	return ret;
}

bool BigInteger::isNegative() const
{
	int negativeFlag = BN_is_negative(this->bigInt);
	return (negativeFlag == 0 ? false : true);
}

std::string BigInteger::toHex() const
{
	char *str = BN_bn2hex(this->bigInt);
	THROW_ENCODE_IF(str == NULL);

	std::string ret(str);
	OPENSSL_free(str);
	return ret;
}

std::string BigInteger::toDec() const
{
	char *str = BN_bn2dec(this->bigInt);
	THROW_ENCODE_IF(str == NULL);

	std::string ret(str);
	OPENSSL_free(str);
	return ret;
}

uint32_t BigInteger::bitSize() const
{
	int size = BN_num_bits(this->bigInt);
	THROW_DECODE_IF(size < 0);

	// CAST: implicit
	return size;
}

void BigInteger::setHexValue(const std::string& hex)
{
	int rc = BN_hex2bn(&this->bigInt, hex.c_str());
	THROW_DECODE_IF(rc == 0);
}

void BigInteger::setDecValue(const std::string& dec)
{
	int rc = BN_dec2bn(&this->bigInt, dec.c_str());
	THROW_DECODE_IF(rc == 0);
}

BigInteger& BigInteger::add(const BigInteger& a)
{
	int rc = BN_add(this->bigInt, this->bigInt, a.bigInt);
	THROW_OPERATION_IF(rc == 0);
	return *this;
}

BigInteger& BigInteger::sub(const BigInteger& a)
{
	int rc = BN_sub(this->bigInt, this->bigInt, a.bigInt);
	THROW_OPERATION_IF(rc == 0);
	return *this;
}

BigInteger& BigInteger::mul(const BigInteger& a)
{
	BN_CTX *ctx = BN_CTX_new();
	THROW_BAD_ALLOC_IF(ctx == NULL);

	BIGNUM *r = BN_new();
	THROW_BAD_ALLOC_AND_FREE_IF(r == NULL,
			BN_CTX_free(ctx);
	);
	
	int rc = BN_mul(r, this->bigInt, a.bigInt, ctx);
	BN_CTX_free(ctx);
	THROW_BAD_ALLOC_AND_FREE_IF(rc == 0,
			BN_free(r);
	);

	this->bigInt = BN_copy(this->bigInt, r);
	BN_free(r);
	THROW_DECODE_IF(this->bigInt == NULL);
	
	return (*this);
}

BigInteger BigInteger::operator*(const BigInteger& a) const
{
	BigInteger tmp(*this);
	return tmp.mul(a);
}

BigInteger& BigInteger::div(const BigInteger& a)
{
	BN_CTX* ctx = NULL;
	BIGNUM* dv = NULL;
	BIGNUM* rem = NULL;
	
	THROW_DIVISION_BY_ZERO_IF(a == 0);
	
	dv = BN_new();
	THROW_BAD_ALLOC_IF(dv == NULL);

	rem = BN_new();
	THROW_BAD_ALLOC_AND_FREE_IF(rem == NULL,
			BN_clear_free(dv);
	);

	ctx = BN_CTX_new();
	THROW_BAD_ALLOC_AND_FREE_IF(rem == NULL,
			BN_clear_free(dv);
			BN_clear_free(rem);
	);

	int rc = BN_div(dv, rem, this->bigInt, a.bigInt, ctx);
	BN_CTX_free(ctx);
	BN_clear_free(rem);
	THROW_OPERATION_AND_FREE_IF(rc == 0,
			BN_clear_free(dv);
	);

	this->bigInt = BN_copy(this->bigInt, dv);
	BN_clear_free(dv);
	THROW_OPERATION_IF(rc == 0);

	return (*this);
}

BigInteger BigInteger::operator/(const BigInteger& a) const
{
	BigInteger ret(*this);
	ret.div(a);
	return ret;
}

BigInteger BigInteger::mod(const BigInteger& divisor) const
{
	THROW_DIVISION_BY_ZERO_IF(divisor == 0);

	BIGNUM *remainder = BN_new();
	THROW_BAD_ALLOC_IF(remainder == NULL);

	BN_CTX *ctx = BN_CTX_new();
	THROW_BAD_ALLOC_AND_FREE_IF(ctx == NULL,
			BN_clear_free(remainder);
	);

	int rc = BN_mod(remainder, this->bigInt, divisor.bigInt, ctx);
	BN_CTX_free(ctx);
	THROW_OPERATION_AND_FREE_IF(rc == 0,
			BN_clear_free(remainder);
	);

	BigInteger ret(remainder);
	return ret;
}

BigInteger BigInteger::operator%(const BigInteger& divisor) const
{
	return this->mod(divisor);
}

int BigInteger::compare(const BigInteger& a) const noexcept
{
	int ret = BN_cmp(this->bigInt, a.bigInt);
	return ret;
}

BigInteger BigInteger::operator+(const BigInteger& c) const
{
	BigInteger ret(*this);
	return ret.add(c);
}

BigInteger& BigInteger::operator+=(const BigInteger& c)
{
	return this->add(c);
}

BigInteger BigInteger::operator-(const BigInteger& c) const
{
	BigInteger ret(*this);
	return ret.sub(c);
}

bool BigInteger::operator==(const BigInteger& c) const
{
	return this->compare(c) == 0;
}

bool BigInteger::operator!=(const BigInteger& c) const
{
	return this->compare(c) != 0;
}

bool BigInteger::operator>(const BigInteger& c) const
{
	return this->compare(c) == 1;
}

bool BigInteger::operator>=(const BigInteger& c) const
{
	return (this->compare(c) >= 0);
}

bool BigInteger::operator<(const BigInteger& c) const
{
	return this->compare(c) == -1;
}

bool BigInteger::operator<=(const BigInteger& c) const
{
	return (this->compare(c) <= 0);
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

bool BigInteger::operator&&(const BigInteger& c) const
{
	bool a = !((*this) == 0);
	bool b = !(c == 0);
	
	return a && b;
}


const BIGNUM* BigInteger::getSslObject() const
{
	return this->bigInt;
}

BIGNUM* BigInteger::toSslObject() const
{
	BIGNUM *ret = BN_dup(this->bigInt);
	THROW_ENCODE_ERROR_IF(ret == NULL);
	return ret;
}
