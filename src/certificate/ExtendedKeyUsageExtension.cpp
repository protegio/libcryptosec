#include <libcryptosec/certificate/ExtendedKeyUsageExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_ext_key_usage);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(X509_EXTENSION *ext) :
		Extension(ext)
{
	ObjectIdentifier objectIdentifier;
	STACK_OF(ASN1_OBJECT) *extKeyUsages = NULL;
	ASN1_OBJECT *asn1Obj = NULL;
	ASN1_OBJECT* object = X509_EXTENSION_get_object(ext);
	std::string value;
	int nid;

	if (OBJ_obj2nid(object) != NID_ext_key_usage) {
		throw CertificationException(CertificationException::INVALID_TYPE, "ExtendedKeyUsageExtension::ExtendedKeyUsageExtension");
	}

	extKeyUsages = (STACK_OF(ASN1_OBJECT) *) X509V3_EXT_d2i(ext);
	if (extKeyUsages == 0) {
		throw CertificationException(CertificationException::X509V3_EXT_D2I_ERROR, "ExtendedKeyUsageExtension::ExtendedKeyUsageExtension");
	}

	while(sk_ASN1_OBJECT_num(extKeyUsages) > 0)
	{
		asn1Obj = sk_ASN1_OBJECT_pop(extKeyUsages);
		nid = OBJ_obj2nid(asn1Obj);
		if (nid == NID_undef) {
			// TODO: ok to skip? should we throw an exception?
			continue;
		}

		ObjectIdentifier item(asn1Obj);
		this->usages.push_back(std::move(item));
	}
	sk_ASN1_OBJECT_free(extKeyUsages);
}

ExtendedKeyUsageExtension::~ExtendedKeyUsageExtension()
{
}

std::string ExtendedKeyUsageExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	for (auto usage : this->usages) {
		ret += tab + "<usage>" + usage.getName() + "</usage>\n";
	}
	return ret;
}
void ExtendedKeyUsageExtension::addUsage(const ObjectIdentifier& oid)
{
	// TODO: validar oid?
	this->usages.push_back(oid);
}

std::vector<ObjectIdentifier> ExtendedKeyUsageExtension::getUsages() const
{
	return this->usages;
}

X509_EXTENSION* ExtendedKeyUsageExtension::getX509Extension() const
{
	X509_EXTENSION *ret = NULL;
	ASN1_OBJECT *asn1Obj = NULL;
	STACK_OF(ASN1_OBJECT) *extKeyUsages = NULL;
	unsigned int i = 0;
	int rc = 0;

	extKeyUsages = sk_ASN1_OBJECT_new_null();
	if (extKeyUsages == NULL) {
		throw CertificationException(CertificationException::SK_TYPE_NEW_NULL_ERROR, "ExtendedKeyUsageExtension::getX509Extension");
	}

	for (auto usage : this->usages)	{
		asn1Obj = OBJ_dup(usage.getObjectIdentifier());
		if (asn1Obj == NULL) {
			throw CertificationException(CertificationException::OBJ_DUP_ERROR, "ExtendedKeyUsageExtension::getX509Extension");
		}

		rc = sk_ASN1_OBJECT_push(extKeyUsages, asn1Obj);
		if (rc == 0) {
			throw CertificationException(CertificationException::SK_TYPE_PUSH_ERROR, "ExtendedKeyUsageExtension::getX509Extension");
		}
	}

	ret = X509V3_EXT_i2d(NID_ext_key_usage, this->critical ? 1 : 0, (void *) extKeyUsages);
	if (ret == NULL) {
		throw CertificationException(CertificationException::X509V3_EXT_I2D_ERROR, "ExtendedKeyUsageExtension::getX509Extension");
	}

	sk_ASN1_OBJECT_pop_free(extKeyUsages, ASN1_OBJECT_free);

	return ret;
}
