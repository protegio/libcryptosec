#include <libcryptosec/certificate/extension/ExtendedKeyUsageExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_ext_key_usage);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	THROW_DECODE_ERROR_IF(this->getName() != Extension::EXTENDED_KEY_USAGE);

	STACK_OF(ASN1_OBJECT) *sslObjectStack = (STACK_OF(ASN1_OBJECT) *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_DECODE_ERROR_IF(sslObjectStack == NULL);

	int num = sk_ASN1_OBJECT_num(sslObjectStack);
	for (int i = 0; i < num; i++) {
		const ASN1_OBJECT *sslObject = sk_ASN1_OBJECT_value(sslObjectStack, i);
		THROW_DECODE_ERROR_AND_FREE_IF(sslObject == NULL,
				sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
		);

		try {
			ObjectIdentifier item(sslObject);
			this->usages.push_back(std::move(item));
		} catch (...) {
			sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
			throw;
		}
	}

	sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
}

ExtendedKeyUsageExtension::~ExtendedKeyUsageExtension()
{
}

void ExtendedKeyUsageExtension::addUsage(const ObjectIdentifier& oid)
{
	// TODO: validar oid?
	this->usages.push_back(oid);
}

const std::vector<ObjectIdentifier>& ExtendedKeyUsageExtension::getUsages() const
{
	return this->usages;
}

std::string ExtendedKeyUsageExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	for (auto usage : this->usages) {
		ret += tab + "<usage>" + usage.getName() + "</usage>\n";
	}
	return ret;
}

X509_EXTENSION* ExtendedKeyUsageExtension::getX509Extension() const
{
	STACK_OF(ASN1_OBJECT) *sslObjectStack = sk_ASN1_OBJECT_new_null();
	THROW_ENCODE_ERROR_IF(sslObjectStack == NULL);

	for (auto usage : this->usages)	{
		ASN1_OBJECT *sslObject = NULL;

		try {
			sslObject = usage.getObjectIdentifier();
		} catch (...) {
			sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
			throw;
		}

		int rc = sk_ASN1_OBJECT_push(sslObjectStack, sslObject);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				ASN1_OBJECT_free(sslObject);
				sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_ext_key_usage, this->critical ? 1 : 0, (void *) sslObjectStack);
	sk_ASN1_OBJECT_pop_free(sslObjectStack, ASN1_OBJECT_free);
	THROW_ENCODE_ERROR_IF(ret == 0);

	return ret;
}
