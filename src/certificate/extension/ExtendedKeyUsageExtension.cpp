#include <libcryptosec/certificate/extension/ExtendedKeyUsageExtension.h>

#include <libcryptosec/certificate/ObjectIdentifier.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>

#include <openssl/asn1.h>
#include <openssl/x509v3.h>

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_ext_key_usage);
}

ExtendedKeyUsageExtension::ExtendedKeyUsageExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_ext_key_usage) {
		throw CertificationException(CertificationException::INVALID_TYPE, "ExtendedKeyUsageExtension::ExtendedKeyUsageExtension");
	}

	STACK_OF(ASN1_OBJECT) *extKeyUsages = (STACK_OF(ASN1_OBJECT) *) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (extKeyUsages == NULL) {
		throw CertificationException(CertificationException::X509V3_EXT_D2I_ERROR, "ExtendedKeyUsageExtension::ExtendedKeyUsageExtension");
	}

	while(sk_ASN1_OBJECT_num(extKeyUsages) > 0) {
		ASN1_OBJECT *asn1Obj = sk_ASN1_OBJECT_pop(extKeyUsages);
		if (asn1Obj == NULL) {
			throw CertificationException("" /* TODO */);
		}

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

const std::vector<ObjectIdentifier>& ExtendedKeyUsageExtension::getUsages() const
{
	return this->usages;
}

X509_EXTENSION* ExtendedKeyUsageExtension::getX509Extension() const
{
	X509_EXTENSION *ret = NULL;
	ASN1_OBJECT *asn1Obj = NULL;
	STACK_OF(ASN1_OBJECT) *extKeyUsages = NULL;
	int rc = 0;

	extKeyUsages = sk_ASN1_OBJECT_new_null();
	if (extKeyUsages == NULL) {
		throw CertificationException(CertificationException::SK_TYPE_NEW_NULL_ERROR, "ExtendedKeyUsageExtension::getX509Extension");
	}

	for (auto usage : this->usages)	{
		asn1Obj = usage.getObjectIdentifier();
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
