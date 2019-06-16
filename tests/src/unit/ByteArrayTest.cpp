#include <gtest/gtest.h>

#include <libcryptosec/BigInteger.h>
#include <libcryptosec/ByteArray.h>

/**
 * @brief Testes unitários da classe BigInteger.
 */
class ByteArrayTest: public ::testing::Test {

protected:

	virtual void SetUp() {
	}

	virtual void TearDown() {
	}
};

TEST_F(ByteArrayTest, ByteArrayConstructorTest) {
	ByteArray ba;
	ASSERT_EQ(ba.getSize(), 0);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);
}

TEST_F(ByteArrayTest, ByteArrayUint32ContructorTest) {
	ByteArray ba(0);
	ASSERT_EQ(ba.getSize(), 0);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);

	ba = ByteArray(1);
	ASSERT_EQ(ba.getSize(), 1);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);
}

TEST_F(ByteArrayTest, ByteArrayUint8PointerUint32ConstructorTest) {
	const uint8_t *data = (const uint8_t*) "hello world!";
	uint32_t size = 12;

	ByteArray ba(data, size);
	int cmpResult = memcmp(data, ba.getConstDataPointer(), size);
	ASSERT_EQ(cmpResult, 0);

	ba = ByteArray(data, size-1);
	cmpResult = memcmp(data, ba.getConstDataPointer(), size-1);
	ASSERT_EQ(cmpResult, 0);

	ba = ByteArray(data, 0);
	cmpResult = memcmp(data, ba.getConstDataPointer(), 0);
	ASSERT_EQ(cmpResult, 0);
}

TEST_F(ByteArrayTest, ByteArrayStringConstructorTest) {
	std::string data = "Hello world!";
	uint32_t size = data.size();

	ByteArray ba(data);
	int cmpResult = memcmp(data.c_str(), ba.getConstDataPointer(), size);
	ASSERT_EQ(cmpResult, 0);

	data = "";
	size = data.size();

	ba = ByteArray(data);
	cmpResult = memcmp(data.c_str(), ba.getConstDataPointer(), size);
	ASSERT_EQ(cmpResult, 0);
}

TEST_F(ByteArrayTest, ByteArrayCopyConstructorTest) {
	ByteArray ba1("Hello world!");
	ByteArray ba2(ba1);
	ASSERT_EQ(ba1, ba2);
}

TEST_F(ByteArrayTest, ByteArrayMoveConstructorTest) {
	ByteArray ba1("Hello world!");
	ByteArray ba2(std::move(ba1));
	ASSERT_NE(ba1, ba2);
}

TEST_F(ByteArrayTest, ByteArrayCopyOperatorTest) {
	ByteArray ba1("Hello world!");
	ByteArray ba2("Good bye world!");
	ba2 = ba1;
	ASSERT_EQ(ba1, ba2);
}

TEST_F(ByteArrayTest, ByteArrayMoveOperatorTest) {
	ByteArray ba1("Hello world!");
	ByteArray ba2(ba1);

	ba2 = std::move(ba1);
	ASSERT_NE(ba1, ba2);
}

TEST_F(ByteArrayTest, ByteArrayAtTest) {
	ByteArray ba("0123456789");

	uint8_t c = ba.at(0);
	ASSERT_EQ(c, '0');

	c = ba.at(5);
	ASSERT_EQ(c, '5');

	c = ba.at(ba.getSize()-1);
	ASSERT_EQ(c, '9');

	ASSERT_THROW(ba.at(-1), std::out_of_range);
	ASSERT_THROW(ba.at(ba.getSize()), std::out_of_range);
}

TEST_F(ByteArrayTest, ByteArrayAtOperatorTest) {
	ByteArray ba("0123456789");

	uint8_t c = ba[0];
	ASSERT_EQ(c, '0');

	c = ba[5];
	ASSERT_EQ(c, '5');

	c = ba[ba.getSize()-1];
	ASSERT_EQ(c, '9');

	ASSERT_THROW(ba[-1], std::out_of_range);
	ASSERT_THROW(ba[ba.getSize()], std::out_of_range);
}

TEST_F(ByteArrayTest, ByteArrayEqualOperatorTest) {
	ByteArray ba1("0123456789");
	ByteArray ba2("0123456789");
	ByteArray ba3("9876543210");

	ASSERT_TRUE(ba1 == ba1);
	ASSERT_TRUE(ba2 == ba2);
	ASSERT_TRUE(ba3 == ba3);
	ASSERT_TRUE(ba1 == ba2);
	ASSERT_TRUE(ba2 == ba1);
	ASSERT_FALSE(ba1 == ba3);
	ASSERT_FALSE(ba3 == ba1);
	ASSERT_FALSE(ba2 == ba3);
	ASSERT_FALSE(ba3 == ba2);
}

TEST_F(ByteArrayTest, ByteArrayNotEqualOperatorTest) {
	ByteArray ba1("0123456789");
	ByteArray ba2("0123456789");
	ByteArray ba3("9876543210");

	ASSERT_FALSE(ba1 != ba1);
	ASSERT_FALSE(ba2 != ba2);
	ASSERT_FALSE(ba3 != ba3);
	ASSERT_FALSE(ba1 != ba2);
	ASSERT_FALSE(ba2 != ba1);
	ASSERT_TRUE(ba1 != ba3);
	ASSERT_TRUE(ba3 != ba1);
	ASSERT_TRUE(ba2 != ba3);
	ASSERT_TRUE(ba3 != ba2);
}

TEST_F(ByteArrayTest, ByteArrayXorOperatorTest) {
	uint8_t data0[3] = {0x00, 0x00, 0x00};
	uint8_t data1[3] = {0x00, 0xFF, 0x00};
	uint8_t data2[3] = {0x00, 0xFF, 0x00};
	uint8_t data3[3] = {0xF0, 0xF0, 0xF0};
	uint8_t data4[3] = {0xF0, 0x0F, 0xF0};

	ByteArray ba0(data0, 3);
	ByteArray ba1(data1, 3);
	ByteArray ba2(data2, 3);
	ByteArray ba3(data3, 3);
	ByteArray ba4(data4, 3);

	ByteArray xorResult = ba0 xor ba0;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba1 xor ba1;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba2 xor ba2;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba3 xor ba3;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba4 xor ba4;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba1 xor ba2;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba2 xor ba1;
	ASSERT_EQ(xorResult, ba0);

	xorResult = ba1 xor ba3;
	ASSERT_EQ(xorResult, ba4);

	xorResult = ba3 xor ba1;
	ASSERT_EQ(xorResult, ba4);

	xorResult = ba2 xor ba3;
	ASSERT_EQ(xorResult, ba4);

	xorResult = ba3 xor ba2;
	ASSERT_EQ(xorResult, ba4);

	uint8_t data5[4] = {0xAA, 0x00, 0xFF, 0x00};
	uint8_t data6[4] = {0xAA, 0xFF, 0xFF, 0x00};

	ByteArray ba5(data5, 4);
	ByteArray ba6(data6, 4);

	xorResult = ba1 xor ba5;
	ASSERT_EQ(xorResult, ba6);

	xorResult = ba5 xor ba1;
	ASSERT_EQ(xorResult, ba6);
}

TEST_F(ByteArrayTest, ByteArrayCopyTest) {
	ByteArray ba0("0123456789");
	ByteArray ba1("9876543210");
	ByteArray ba3;

	ba3.copy(ba0, 0, 0, 10);
	ASSERT_EQ(ba3, ByteArray("0123456789"));

	ba3.copy(ba0, 0, 0, 10);
	ASSERT_EQ(ba3, ByteArray("0123456789"));

	ba3.copy(ba1, 0, 0, 10);
	ASSERT_EQ(ba3, ByteArray("9876543210"));

	ba3.copy(ba0, 0, 10, 10);
	ASSERT_EQ(ba3, ByteArray("98765432100123456789"));

	ba3.copy(ba0, 0, 0, 10);
	ASSERT_EQ(ba3, ByteArray("01234567890123456789"));

	ba3.copy(ba0, 5, 3, 2);
	ASSERT_EQ(ba3, ByteArray("01256567890123456789"));

	ASSERT_THROW(ba3.copy(ba0, UINT32_MAX, 0, 1), std::overflow_error);
	ASSERT_THROW(ba3.copy(ba0, 0, UINT32_MAX, 1), std::overflow_error);
	ASSERT_THROW(ba3.copy(ba0, 0, 0, ba0.getSize() + 1), std::out_of_range);
	ASSERT_THROW(ba3.copy(ba0, 1, 0, ba0.getSize()), std::out_of_range);
}

TEST_F(ByteArrayTest, ByteArrayGetConstDataPointerTest) {
	ByteArray ba0("0123456789");
	const uint8_t* data = ba0.getConstDataPointer();
	int compResult = memcmp(data, "0123456789", ba0.getSize());
	ASSERT_EQ(compResult, 0);
}

TEST_F(ByteArrayTest, ByteArrayGetDataPointerTest) {
	ByteArray ba0("0123456789");
	uint8_t* data = ba0.getDataPointer();
	int compResult = memcmp(data, "0123456789", ba0.getSize());
	ASSERT_EQ(compResult, 0);

	data[0] = '9';
	const uint8_t* constData = ba0.getConstDataPointer();
	compResult = memcmp(constData, "9123456789", ba0.getSize());
	ASSERT_EQ(compResult, 0);

	ASSERT_EQ(ba0, ByteArray("9123456789"));
}

TEST_F(ByteArrayTest, ByteArrayGetSizeTest) {
	ByteArray ba0("0123456789");
	ASSERT_EQ(ba0.getSize(), 10);
}

TEST_F(ByteArrayTest, ByteArraySetSizeTest) {
	ByteArray ba0("0123456789");
	ByteArray ba1("0123456789");

	ba0.setSize(5);
	ASSERT_EQ(ba0.getSize(), 5);
	ASSERT_NE(ba0, ba1);
	ASSERT_THROW(ba0.at(5), std::out_of_range);

	ba0.setSize(10);
	ASSERT_EQ(ba0.getSize(), 10);
	ASSERT_EQ(ba0, ba1);
	ASSERT_NO_THROW(ba0.at(5));

	ba0.setSize(15);
	ASSERT_EQ(ba0.getSize(), 15);
	ASSERT_NE(ba0, ba1);
	ASSERT_NO_THROW(ba0.at(10));
}

TEST_F(ByteArrayTest, ByteArrayToStringTest) {
	ByteArray ba0("0123456789");
	std::string ba0String = ba0.toString();
	ASSERT_EQ(ba0String, "0123456789");
}

TEST_F(ByteArrayTest, ByteArrayToHexTest) {
	const uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	ByteArray ba0(data, 4);

	std::string ba0HEx = ba0.toHex();
	ASSERT_EQ(ba0HEx, "DEADBEEF");

	ba0HEx = ba0.toHex(':');
	ASSERT_EQ(ba0HEx, "DE:AD:BE:EF");
}

TEST_F(ByteArrayTest, ByteArrayGetAsn1OctetStringTest) {
	const uint8_t data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	ByteArray ba0(data, 4);

	ASN1_OCTET_STRING *octetString = ba0.getAsn1OctetString();

	int size = ASN1_STRING_length(octetString);
	ASSERT_EQ(size, 4);

	const uint8_t *octetStringData = ASN1_STRING_get0_data(octetString);
	int compResult = memcmp(octetStringData, data, 4);
	ASSERT_EQ(compResult, 0);
}

TEST_F(ByteArrayTest, ByteArrayBurnTest) {
	const uint8_t cmpData[4] = {0x00, 0x00, 0x00, 0x00};
	const char *cmpStr = "0123";
	ByteArray ba0("0123");
	ByteArray ba1("0123");

	ba0.burn(false);
	int compResult = memcmp(ba0.getConstDataPointer(), cmpData, 4);
	ASSERT_EQ(compResult, 0);

	// Teoricamente esse teste pode falhar, mas a probabilidade é
	// muito baixa (i.e.: ~ 1/2^32).
	ba1.burn(true);
	compResult = memcmp(ba1.getConstDataPointer(), cmpData, 4);
	ASSERT_NE(compResult, 0);
	compResult = memcmp(ba1.getConstDataPointer(), cmpStr, 4);
	ASSERT_NE(compResult, 0);
}
