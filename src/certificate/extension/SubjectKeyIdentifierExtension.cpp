#include <libcryptosec/certificate/extension/SubjectKeyIdentifierExtension.h>

#include <libcryptosec/exception/CertificationException.h>
#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/Base64.h>

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_subject_key_identifier);
}

SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension(const X509_EXTENSION* ext) :
		Extension(ext)
{
	const ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_subject_key_identifier) {
		throw CertificationException(CertificationException::INVALID_TYPE, "SubjectKeyIdentifierExtension::SubjectKeyIdentifierExtension");
	}

	ASN1_OCTET_STRING *octetString = (ASN1_OCTET_STRING*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (octetString == NULL) {
		throw CertificationException("" /* TODO */);
	}

	this->keyIdentifier = std::move(ByteArray(octetString->data, octetString->length));

	ASN1_OCTET_STRING_free(octetString);
}

SubjectKeyIdentifierExtension::~SubjectKeyIdentifierExtension()
{
}

void SubjectKeyIdentifierExtension::setKeyIdentifier(const ByteArray& keyIdentifier)
{
	this->keyIdentifier = keyIdentifier;
}

const ByteArray& SubjectKeyIdentifierExtension::getKeyIdentifier() const
{
	return this->keyIdentifier;
}

std::string SubjectKeyIdentifierExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<subjectKeyIdentifier>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->critical ? "yes" : "no");
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>" + Base64::encode(this->keyIdentifier) + "</extnValue>\n";
	ret += tab + "</subjectKeyIdentifier>\n";
	return ret;
}

std::string SubjectKeyIdentifierExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret;
	ret += tab + "<keyIdentifier>" + Base64::encode(this->keyIdentifier) + "</keyIdentifier>\n";
	return ret;
}

X509_EXTENSION* SubjectKeyIdentifierExtension::getX509Extension() const
{
	ASN1_OCTET_STRING *octetString = ASN1_OCTET_STRING_new();
	if (octetString == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int rc = ASN1_OCTET_STRING_set(octetString, this->keyIdentifier.getConstDataPointer(), this->keyIdentifier.getSize());
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_subject_key_identifier, this->critical ? 1 : 0, (void*) octetString);
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	return ret;
}
