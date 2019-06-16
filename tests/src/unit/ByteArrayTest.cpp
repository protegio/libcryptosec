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

TEST_F(ByteArrayTest, ByteArrayTest) {
	ByteArray ba;
	ASSERT_EQ(ba.getSize(), 0);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);
}

TEST_F(ByteArrayTest, ByteArrayUint32Test) {
	ByteArray ba(0);
	ASSERT_EQ(ba.getSize(), 0);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);

	ba = ByteArray(1);
	ASSERT_EQ(ba.getSize(), 1);
	ASSERT_NE(ba.getConstDataPointer(), nullptr);
}

TEST_F(ByteArrayTest, ByteArrayUint8PointerUint32Test) {
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

TEST_F(ByteArrayTest, ByteArrayStringTest) {
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

TEST_F(ByteArrayTest, ByteArrayCopyTest) {
	ByteArray ba1("Hello world!");
	ByteArray ba2(ba1);
	ASSERT_EQ(ba1, ba2);
}

TEST_F(ByteArrayTest, ByteArrayMoveTest) {
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
