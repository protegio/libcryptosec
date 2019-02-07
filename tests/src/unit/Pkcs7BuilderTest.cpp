#include <libcryptosec/pkcs7/Pkcs7Builder.h>
#include <libcryptosec/pkcs7/Pkcs7.h>

#include <libcryptosec/certificate/CertificateBuilder.h>
#include <libcryptosec/certificate/RDNSequence.h>
#include <libcryptosec/KeyPair.h>
#include <libcryptosec/PrivateKey.h>

#include <libcryptosec/Random.h>
#include <libcryptosec/SymmetricKey.h>

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <map>

const std::string testString = "The quick brown fox jumps over the lazy dog";

const std::string testCertificatePem = "-----BEGIN CERTIFICATE-----\n"
"MIIDtDCCApygAwIBAgIJAOSKti4IY0aqMA0GCSqGSIb3DQEBCwUAMG8xCzAJBgNV\n"
"BAYTAkJSMQswCQYDVQQIDAJTUDERMA8GA1UEBwwIQ2FtcGluYXMxETAPBgNVBAoM\n"
"CFByb3RlZ2lvMRUwEwYDVQQLDAxMaWJjcnlwdG9zZWMxFjAUBgNVBAMMDUZ1bGFu\n"
"byBkZSBUYWwwHhcNMTkwMjA2MjIxNzU3WhcNMTkwMzA4MjIxNzU3WjBvMQswCQYD\n"
"VQQGEwJCUjELMAkGA1UECAwCU1AxETAPBgNVBAcMCENhbXBpbmFzMREwDwYDVQQK\n"
"DAhQcm90ZWdpbzEVMBMGA1UECwwMTGliY3J5cHRvc2VjMRYwFAYDVQQDDA1GdWxh\n"
"bm8gZGUgVGFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwoP+dd/\n"
"o0EitD3aLYeikN6XmdQRWbd03j1bjqnGT3inh634dQwvJ9SQjglfU7PB9d27xda2\n"
"CU5IAfKPb51Hc9glwhG585SZ0bD20cPMbQ3i6SRl9N0EzoQzfMfsiH5OeSEzCYop\n"
"gs6BxJbWGUeqA2xxki31Ri14a/zSVSmNjXZyViWFJ1nF3Fxqb9vZorUXEmlltA8q\n"
"2nH5Dkp4U1H6fQVBrT4p1hYR2XcrCX0Tj907Vk/OfYtEuRX1GNEvv+H2ItCa1inJ\n"
"sd+DvUwLNRo62t8+E1DRZvmh5kTCQkn16JLnhxl7QxN/MIh4GvwiSxGO9FmMycas\n"
"Jbf1oeYyA6bXXQIDAQABo1MwUTAdBgNVHQ4EFgQUpOMqWn5UoG6SrNlugF3g/gbx\n"
"wQAwHwYDVR0jBBgwFoAUpOMqWn5UoG6SrNlugF3g/gbxwQAwDwYDVR0TAQH/BAUw\n"
"AwEB/zANBgkqhkiG9w0BAQsFAAOCAQEATwrYK5BTHe9NpKdbh0lcJs0N7K+WO8Vd\n"
"pN+a/Meyb/6XCWPz4jbhfHhRP7Ngm4ZVI1vfD4k6N78FIpGZ7Q2jYknXad0xFsbs\n"
"afchrHmcGQBIaLHE6sBWthictCmF/m0uHuqtI+1WXcCmVIS/VHnm7DhDB8KXLuZA\n"
"eHn4dgQE5TWcQEsj2GJdsKfNDfimasg46LABgDyh00nsSDKCanrVEPzHPQKhfLGT\n"
"rj+Uhp/eUy/6tz3Hy7ejCLC5Gyt87ciAAKCjH/hnaDam/AjKfxDc1oXmnv47vZfm\n"
"723R5FhcrHIBz7+f+Z3zc1kkgRqnJK8NMAeFp/uQDASnEDHaHv932A==\n"
"-----END CERTIFICATE-----";

const std::string testPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCrCg/513+jQSK0\n"
"Pdoth6KQ3peZ1BFZt3TePVuOqcZPeKeHrfh1DC8n1JCOCV9Ts8H13bvF1rYJTkgB\n"
"8o9vnUdz2CXCEbnzlJnRsPbRw8xtDeLpJGX03QTOhDN8x+yIfk55ITMJiimCzoHE\n"
"ltYZR6oDbHGSLfVGLXhr/NJVKY2NdnJWJYUnWcXcXGpv29mitRcSaWW0DyracfkO\n"
"SnhTUfp9BUGtPinWFhHZdysJfROP3TtWT859i0S5FfUY0S+/4fYi0JrWKcmx34O9\n"
"TAs1Gjra3z4TUNFm+aHmRMJCSfXokueHGXtDE38wiHga/CJLEY70WYzJxqwlt/Wh\n"
"5jIDptddAgMBAAECggEBAJSdpK4Rer1uzmnQyLABB9dbIl0ucHkFOE4XAGQgzsik\n"
"7OSu3JFPqfWw9H4GVMdVDTbGmO7ZlsjVNSpECjAQeFKHQJ+1aV7mAxW572zq9cjY\n"
"ZQ7xaonuNcwAAQDucm9TWHpVx5QFcfZP21/nNFc49tgMtU4wEswMnHMwdc470dxU\n"
"3ywSvKCRcRPuNPGM7pJa/wV/pg9UETGMPuOpbzu2BqdR9Fx2+CaJdmDt2rnE1OKM\n"
"J+xcx/B8KFFluvBVR2FeMf0shie+hOcUfwyvhBtvPf0+wftNOQcsnwtqfnkDxcRq\n"
"LVp8DnydDS6aNCpnyWTwM0q2uzLdhXSTq1jiY68XaIECgYEA46By0e1es/JxOsB1\n"
"s9rxCyIWlSkZ5LECVFBVKbeM/XYRsIiWcJfJNh9SU2rDYDq3SyoGrj2PAUPEpI1J\n"
"h17sz6rVPNAHKqcgXkSK6c1R63fW8jZjD1iz1DqIcloL7GxRYQXECrwYNXSZwoQG\n"
"nvfzlmzA6re8fQOYSvkkcJULCv0CgYEAwFvpu07igyV5hDY9VPAB73YtC3v5S5XS\n"
"fXSoFSwnBF3qWRYJ4atyAEUS5upmt+qYF4r2rjEWL5JnWtk9QeUZAoHJ9sqEOeAl\n"
"F3w0WAI+eWHZ6PpvzL6ShhQrbxz18necvviV9cXYXOZ3v6ul2RQuVEMXukWcE8gm\n"
"HRY764fnm+ECgYEA1dy7xCym256fb7m/XHoKGpGucfopz8nXDGxld0py9vhlal0K\n"
"K0MQ0v7elG0sn07LQ516pV5E68VGDeyI9tzi1cIFkptJAHQBX1A6y6wSmY8ArpUW\n"
"wSZv3qgX5ohfx4OFegi2xfcvL5oblLwClH0VqXEIV/7E4xfrkBVAfV4q/+kCgYA7\n"
"jPjqLPzA/xwEi0onfnoK6Tn+wS2nccWNY00Z6OZXWr/PPpxmic4sOTYl2NFeBLl7\n"
"KGFAAiBNL/ThUjm9qbA5b3bX+VBAHp09DQ2jZWZz65ArqURtTV5NNfdQWdXmb5NO\n"
"J+U9Bjf6YrsV0ozwjGffXDn/R8eO9DqgbJ62Rwez4QKBgHMLrJmfuBoYQjegEQeA\n"
"1GIraq65LwnKV9fztnQcJ8iST+3pYEeu8Lzt9MucOyQIDRzQnbRinllc7pvhES/M\n"
"SVWcX1seKVYqlYPpqsj3xMvtCNVn2BQYeoEIhPhkxSAW75WxhGGs9/wiqje69bPh\n"
"gNONzA9l95rOxUtdmYNgdmPI\n"
"-----END PRIVATE KEY-----";

/**
 * @brief Testes unitários da classe CertificateBuilder.
 */
class Pkcs7BuilderTest : public ::testing::Test {

protected:
	virtual void SetUp() {
	}

    virtual void TearDown() {
    }

    Pkcs7Builder builder;
};

/**
 * @brief Testa a função EVP_MD* GetMessageDigest(MessageDigest::Algorithm).
 */
TEST_F(Pkcs7BuilderTest, DataMode) {
	std::ostringstream ss(std::stringstream::binary);

	builder.initData();
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");
}

TEST_F(Pkcs7BuilderTest, DigestedMode) {
	std::ostringstream ss(std::stringstream::binary);
	builder.initDigested(MessageDigest::SHA1);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");
}

TEST_F(Pkcs7BuilderTest, EncryptedMode) {
	SymmetricKey symmetricKey(SymmetricKey::AES_256);
	ByteArray iv = Random::bytes(symmetricKey.getAlgorithmIvSize());

	std::ostringstream ss(std::stringstream::binary);
	builder.initEncrypted(symmetricKey, iv, SymmetricCipher::CBC);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	pkcs7.extract(ss);
	std::string extracted = ss.str();
	EXPECT_EQ(extracted, testString);
	ss.str("");
}

TEST_F(Pkcs7BuilderTest, SignedMode) {
	Certificate certificate(testCertificatePem);
	PrivateKey privateKey(testPrivateKeyPem);

	std::stringstream ss;
	builder.initSigned(true);
	builder.addSigner(MessageDigest::SHA256, certificate, privateKey);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	std::cout << pkcs7.getPemEncoded() << std::endl;
	bool valid = pkcs7.verifyAndExtract(ss);
	std::string extracted = ss.str();
	EXPECT_TRUE(valid);
	EXPECT_EQ(testString, extracted);
}

TEST_F(Pkcs7BuilderTest, SignedModeNoSigner) {
	std::stringstream ss;
	builder.initSigned(true);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	std::cerr << pkcs7.getPemEncoded() << std::endl;
	bool valid = pkcs7.verifyAndExtract(ss);
	std::string extracted = ss.str();
	EXPECT_TRUE(valid);
	EXPECT_EQ(testString, extracted);
}

TEST_F(Pkcs7BuilderTest, EnvelopedMode) {
	Certificate certificate(testCertificatePem);
	PrivateKey privateKey(testPrivateKeyPem);

	std::stringstream ss;
	builder.initEnveloped(SymmetricKey::AES_256, SymmetricCipher::CBC);
	builder.addRecipient(certificate);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	std::cerr << pkcs7.getPemEncoded() << std::endl;
	pkcs7.decrypt(certificate, privateKey, ss);
	std::string extracted = ss.str();
	EXPECT_EQ(testString, extracted);
}

TEST_F(Pkcs7BuilderTest, EnvelopedModeNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedMode) {
	Certificate certificate(testCertificatePem);
	PrivateKey privateKey(testPrivateKeyPem);

	std::stringstream ss;
	builder.initSignedAndEnveloped(SymmetricKey::AES_256, SymmetricCipher::CBC);
	builder.addSigner(MessageDigest::SHA256, certificate, privateKey);
	builder.addRecipient(certificate);
	builder.update(testString);
	Pkcs7 pkcs7 = builder.doFinal();
	std::cerr << pkcs7.getPemEncoded() << std::endl;
	bool valid = pkcs7.verify(true);
	pkcs7.decrypt(certificate, privateKey, ss);
	std::string extracted = ss.str();
	EXPECT_TRUE(valid);
	EXPECT_EQ(testString, extracted);
}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoSigner) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, SignedAndEnvelopedModeNoSignerAndNoRecipient) {

}

TEST_F(Pkcs7BuilderTest, BadStates) {

}

TEST_F(Pkcs7BuilderTest, Reset) {

}

