#include <libcryptosec/pkcs12/Pkcs12Factory.h>

#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/ByteArray.h>

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1.h>

Pkcs12 Pkcs12Factory::fromDerEncoded(const ByteArray& derEncoded)
{
	PKCS12 *pkcs12 = NULL;
	DECODE_DER(pkcs12, derEncoded, d2i_PKCS12_bio);
	Pkcs12 ret(pkcs12);
	return ret;
}
