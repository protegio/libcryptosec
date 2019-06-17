#include <gtest/gtest.h>

#include <libcryptosec/DateTime.h>

#include <time.h>

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class DateTimeTest : public ::testing::Test {

protected:
	time_t rawtime;
	struct tm *timeinfo;
	virtual void SetUp() {
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
	}

	virtual void TearDown() {
	}

};

TEST_F(DateTimeTest, DateTimeConstructorTest) {
	DateTime dt;
}

TEST_F(DateTimeTest, DateTimeTimeTConstructorTest) {
	DateTime dt(this->rawtime);
}

TEST_F(DateTimeTest, DateTimeBigIntegerConstructorTest) {
	BigInteger seconds(this->rawtime);
	DateTime dt(seconds);
}

TEST_F(DateTimeTest, DateTimeAsn1TimeConstructorTest) {
	ASN1_TIME *asn1Time = ASN1_TIME_new();
	ASN1_TIME_set(asn1Time, this->rawtime);
	DateTime dt(asn1Time);
}

TEST_F(DateTimeTest, DateTimeStringConstructorTest) {
	std::string utcTime = "190616121710Z";
	std::string generalizedTime = "20190616121710Z";
	DateTime dt0(utcTime);
	DateTime dt1(generalizedTime);
}

TEST_F(DateTimeTest, DateTimeSetSecondsTest) {
	DateTime dt;
	dt.setSeconds(BigInteger("3121439528", 10));
}

TEST_F(DateTimeTest, DateTimeGetSecondsTest) {
	DateTime dt;
	dt.setSeconds(BigInteger("3121439528", 10));
	dt.getSeconds();
}

TEST_F(DateTimeTest, DateTimeToTimeTTest) {
	DateTime dt(this->rawtime);
	time_t epoch = dt.toTimeT();
	ASSERT_EQ(epoch, this->rawtime);
}

TEST_F(DateTimeTest, DateTimeToAsnTimeTest) {
	DateTime dt(this->rawtime);
	ASSERT_NO_THROW(dt.toAsn1Time());
}

TEST_F(DateTimeTest, DateTimeToAsn1UtcTimeTest) {
	DateTime dt(this->rawtime);
	ASSERT_NO_THROW(dt.toAsn1UTCTime());
}

TEST_F(DateTimeTest, DateTimeToAsn1GeneralizedTimeTest) {
	DateTime dt(this->rawtime);
	ASSERT_NO_THROW(dt.toAsn1GeneralizedTime());
}

TEST_F(DateTimeTest, DateTimeToIsoDateTimeTest) {
	DateTime dt(this->rawtime);
	std::string isoDateTime = dt.toISODateTime();
}

TEST_F(DateTimeTest, DateTimeAddSecondsTest) {
	DateTime dt(this->rawtime);
	dt.addSeconds(65);
}

TEST_F(DateTimeTest, DateTimeAddMinutesTest) {
	DateTime dt(this->rawtime);
	dt.addMinutes(65);
}

TEST_F(DateTimeTest, DateTimeAddHoursTest) {
	DateTime dt(this->rawtime);
	dt.addHours(29);
}

TEST_F(DateTimeTest, DateTimeAddDaysTest) {
	DateTime dt(this->rawtime);
	dt.addDays(370);
}

TEST_F(DateTimeTest, DateTimeAddYearsTest) {
	DateTime dt(this->rawtime);
	dt.addYears(5);
}

TEST_F(DateTimeTest, DateTimeEqualToOperatorTest) {
	DateTime dt0(this->rawtime);
	DateTime dt1(this->rawtime);
	ASSERT_TRUE(dt0 == dt1);
}

TEST_F(DateTimeTest, DateTimeNotEqualToOperatorTest) {
	DateTime dt0(this->rawtime);
	DateTime dt1(this->rawtime);
	ASSERT_FALSE(dt0 != dt1);
	dt1.addSeconds(1);
	ASSERT_TRUE(dt0 != dt1);
}

TEST_F(DateTimeTest, DateTimeLessThanOperatorTest) {
	DateTime dt0(this->rawtime);
	DateTime dt1(this->rawtime);
	ASSERT_FALSE(dt0 < dt1);
	dt1.addSeconds(1);
	ASSERT_TRUE(dt0 < dt1);
}

TEST_F(DateTimeTest, DateTimeGreaterThanOperatorTest) {
	DateTime dt0(this->rawtime);
	DateTime dt1(this->rawtime);
	ASSERT_FALSE(dt0 > dt1);
	dt1.addSeconds(1);
	ASSERT_TRUE(dt1 > dt0);
}

TEST_F(DateTimeTest, DateTimeLessOrEqualThanOperatorTest) {
	DateTime dt0(this->rawtime);
	DateTime dt1(this->rawtime);
	ASSERT_TRUE(dt0 <= dt1);
	dt1.addSeconds(1);
	ASSERT_TRUE(dt0 <= dt1);
}

TEST_F(DateTimeTest, DateTimeGetDateValTest) {
	DateTime dt0(this->rawtime);
	DateTime::getDateVal(dt0.getSeconds());
}

TEST_F(DateTimeTest, DateTimeDate2epochStringTest) {
	DateTime::date2epoch("190616211101Z");
}

TEST_F(DateTimeTest, DateTimeDate2epochUint32Test) {
	DateTime::date2epoch(2019, 5, 16, 21, 12, 01);
}

TEST_F(DateTimeTest, DateTimeGetDayOfWeekTest) {
	DateTime::getDayOfWeek(2019, 5, 16);
}

TEST_F(DateTimeTest, DateTimeIsLeapYearTest) {
	ASSERT_FALSE(DateTime::isLeapYear(2019));
	ASSERT_TRUE(DateTime::isLeapYear(2020));
}

TEST_F(DateTimeTest, DateTimeGetYearSizeTest) {
	ASSERT_EQ(DateTime::getYearSize(2019), 365);
	ASSERT_EQ(DateTime::getYearSize(2020), 366);
}

TEST_F(DateTimeTest, DateTimeGetMonthSizeTest) {
	ASSERT_EQ(DateTime::getMonthSize(1, 2019), 28);
	ASSERT_EQ(DateTime::getMonthSize(1, 2020), 29);
}
