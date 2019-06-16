#include <gtest/gtest.h>

#include <libcryptosec/BigInteger.h>
#include <libcryptosec/ByteArray.h>

/**
 * @brief Testes unitários da classe BigInteger.
 */
class BigIntegerTest: public ::testing::Test {

protected:
	BigInteger negativeOne;
	BigInteger zero;
	BigInteger one;
	BigInteger two;
	BigInteger max64Uint;

	virtual void SetUp() {
		this->negativeOne = BigInteger(-1);
		this->zero = BigInteger(0);
		this->one = BigInteger(1);
		this->two = BigInteger(2);
		this->max64Uint = BigInteger(UINT64_MAX);
	}

	virtual void TearDown() {
	}
};

TEST_F(BigIntegerTest, BigIntegerTest) {
	BigInteger bigInt;
	ASSERT_EQ(bigInt, 0);
}

TEST_F(BigIntegerTest, BigIntegerBignumTest) {
	BIGNUM *bigNum = BN_new();
	BN_set_word(bigNum, 1);
	BigInteger bigInt(bigNum);
	ASSERT_EQ(bigInt, 1);
	BN_free(bigNum);
}

TEST_F(BigIntegerTest, BigIntegerInt64Int32Test) {
	BigInteger zero(0);
	ASSERT_EQ(zero, 0);

	BigInteger one(1);
	ASSERT_EQ(one, 1);

	BigInteger negativeOne(-1);
	ASSERT_EQ(negativeOne, -1);

	BigInteger int32Max(INT32_MAX);
	ASSERT_EQ(int32Max, INT32_MAX);

	BigInteger int32Min(INT32_MIN);
	ASSERT_EQ(int32Min, INT32_MIN);

	BigInteger uInt32Max(UINT32_MAX);
	ASSERT_EQ(uInt32Max, UINT32_MAX);

	BigInteger int64Max(INT64_MAX);
	ASSERT_EQ(int64Max, INT64_MAX);

	BigInteger int64Min(INT64_MIN);
	ASSERT_EQ(int64Min, INT64_MIN);

	BigInteger uInt64Max(UINT64_MAX);
	ASSERT_EQ(uInt64Max, UINT64_MAX);
}

TEST_F(BigIntegerTest, BigIntegerAsn1IntegerTest) {
	ASN1_INTEGER *asn1Int = ASN1_INTEGER_new();
	ASN1_INTEGER_set(asn1Int, 1);
	BigInteger bigInt(asn1Int);
	ASSERT_EQ(bigInt, 1);
	ASN1_INTEGER_free(asn1Int);
}

TEST_F(BigIntegerTest, BigIntegerByteArrayTest) {
	int64_t value = 0xABCDEF00;
	unsigned char dataPointer[4];

	dataPointer[0] = 0xAB;
	dataPointer[1] = 0xCD;
	dataPointer[2] = 0xEF;
	dataPointer[3] = 0x00;

	ByteArray byteArrayInt(dataPointer, 4);
	BigInteger bigInt(byteArrayInt);
	BigInteger bValue(value);
	ASSERT_EQ(bigInt, value);
}

TEST_F(BigIntegerTest, BigIntegerStringIntTest) {
	BigInteger ten("10");
	ASSERT_EQ(ten, 10);
	BigInteger sixteen("10", 16);
	ASSERT_EQ(sixteen, 0x10);
}

TEST_F(BigIntegerTest, BigIntegerSum) {
	BigInteger negativeOnePlusNegativeOne = this->negativeOne + this->negativeOne;
	ASSERT_EQ(negativeOnePlusNegativeOne, -2);

	BigInteger zeroPlusNegativeOne = this->zero + this->negativeOne;
	ASSERT_EQ(zeroPlusNegativeOne, this->negativeOne);

	BigInteger onePlusNegativeOne = this->one + this->negativeOne;
	ASSERT_EQ(onePlusNegativeOne, this->zero);

	BigInteger zeroPlusZero = this->zero + this->zero;
	ASSERT_EQ(zeroPlusZero, this->zero);

	BigInteger onePlusZero = this->one + this->zero;
	ASSERT_EQ(onePlusZero, this->one);

	BigInteger zeroPlusOne = this->zero + this->one;
	ASSERT_EQ(zeroPlusOne, this->one);

	BigInteger onePlusOne = this->one + this->one;
	ASSERT_EQ(onePlusOne, this->two);

	BigInteger max64UintPlusOne = this->max64Uint + this->one;
	ASSERT_EQ(max64UintPlusOne, BigInteger("18446744073709551616"));

	BigInteger max64UintPlusmax64Uint = this->max64Uint + this->max64Uint;
	ASSERT_EQ(max64UintPlusmax64Uint, BigInteger("36893488147419103230"));
}

TEST_F(BigIntegerTest, BigIntegerSubtract) {
	BigInteger negativeOneMinusNegativeOne = this->negativeOne - this->negativeOne;
	ASSERT_EQ(negativeOneMinusNegativeOne, this->zero);

	BigInteger zeroMinusNegativeOne = this->zero - this->negativeOne;
	ASSERT_EQ(zeroMinusNegativeOne, this->one);

	BigInteger oneMinusNegativeOne = this->one - this->negativeOne;
	ASSERT_EQ(oneMinusNegativeOne, this->two);

	BigInteger zeroMinusZero = this->zero - this->zero;
	ASSERT_EQ(zeroMinusZero, this->zero);

	BigInteger oneMinusZero = this->one - this->zero;
	ASSERT_EQ(oneMinusZero, this->one);

	BigInteger zeroMinusOne = this->zero - this->one;
	ASSERT_EQ(zeroMinusOne, this->negativeOne);

	BigInteger oneMinusOne = this->one - this->one;
	ASSERT_EQ(oneMinusOne, this->zero);

	BigInteger max64UintMinusOne = this->max64Uint - this->one;
	ASSERT_EQ(max64UintMinusOne, UINT64_MAX - 1);

	BigInteger max64UintMinusmax64Uint = this->max64Uint - this->max64Uint;
	ASSERT_EQ(max64UintMinusmax64Uint, 0);
}
