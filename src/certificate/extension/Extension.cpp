#include <libcryptosec/certificate/extension/Extension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/Base64.h>
#include <libcryptosec/exception/CertificationException.h>

#include <openssl/x509v3.h>

Extension::Extension() :
	critical(false)
{
}

Extension::Extension(const X509_EXTENSION *ext) :
		objectIdentifier((const ASN1_OBJECT*) X509_EXTENSION_get_object((X509_EXTENSION*) ext)),
		critical(X509_EXTENSION_get_critical(ext) ? true : false)
{
	if (ext == NULL) {
		throw CertificationException(CertificationException::INVALID_EXTENSION, "Extension::Extension");
	}

	const ASN1_OCTET_STRING* value = X509_EXTENSION_get_data((X509_EXTENSION*) ext);
	if (value == NULL) {
		throw CertificationException(CertificationException::INVALID_EXTENSION, "Extension::Extension");
	}
	this->value = std::move(ByteArray(value->data, value->length));
}

Extension::Extension(const std::string& oid, bool critical, const std::string& valueBase64) :
		objectIdentifier(ObjectIdentifierFactory::getObjectIdentifier(oid)),
		critical(critical),
		value(Base64::decode(valueBase64))
{
}

Extension::~Extension()
{
}

std::string Extension::extValue2Xml(const std::string& tab) const
{
	return tab + "<base64Value>\n" +  tab + "\t" + this->getBase64Value() + "\n" + tab + "</base64Value>\n";
}

std::string Extension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, critical;
	ret = tab + "<extension>\n";
		ret += tab + "\t<extnID>"+ this->getName() +"</extnID>\n";
		critical = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>"+ critical +"</critical>\n";
		ret += tab + "\t<extnValue>"+ this->getBase64Value() +"</extnValue>\n";
	ret += tab + "</extension>\n";
	return ret;
}

std::string Extension::toXml(const std::string& tab) const
{
	std::string ret, critical;
	ret = tab + "<extension>\n";
		ret += tab + "\t<extnID>"+ this->getName() +"</extnID>\n";
		ret += tab + "\t<oid>"+ this->getObjectIdentifier().getOid() +"</oid>\n";
		critical = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>"+ critical +"</critical>\n";
		ret += tab + "\t<extnValue>"+ +"\n" + this->extValue2Xml(tab + "\t\t") + tab + "\t</extnValue>\n";
	ret += tab + "</extension>\n";
	return ret;
}

const ObjectIdentifier& Extension::getObjectIdentifier() const
{
	return this->objectIdentifier;
}

std::string Extension::getName() const
{
	return this->objectIdentifier.getName();
}

Extension::Name Extension::getTypeName() const
{
	return Extension::getName(this->objectIdentifier.getNid());
}

const ByteArray& Extension::getValue() const
{
	return this->value; 
}

std::string Extension::getBase64Value() const
{
	return  Base64::encode(this->value);
}

bool Extension::isCritical() const
{
	return this->critical;
}

void Extension::setCritical(bool critical)
{
	this->critical = critical;
}

X509_EXTENSION* Extension::getX509Extension() const
{
	int rc = 0;

	X509_EXTENSION *ret = X509_EXTENSION_new();
	if (ret == NULL) {
		throw CertificationException("" /* TODO */);
	}

	ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
	if (value == NULL) {
		throw CertificationException("" /* TODO */);
	}

	rc = ASN1_OCTET_STRING_set(value, this->value.getConstDataPointer(), this->value.getSize());
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}

	rc = X509_EXTENSION_set_data(ret, value);
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}

	rc = X509_EXTENSION_set_object(ret, this->objectIdentifier.getObjectIdentifier());
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}

	rc = X509_EXTENSION_set_critical(ret, this->critical ? 1 : 0);
	if (rc == 0) {
		throw CertificationException("" /* TODO */);
	}

	return ret;
}

Extension::Name Extension::getName(int nid)
{
	Extension::Name ret;
	switch (nid)
	{
		case NID_key_usage:
			ret = Extension::KEY_USAGE;
			break;
		case NID_ext_key_usage:
			ret = Extension::EXTENDED_KEY_USAGE;
			break;
		case NID_authority_key_identifier:
			ret = Extension::AUTHORITY_KEY_IDENTIFIER;
			break;
		case NID_crl_distribution_points:
			ret = Extension::CRL_DISTRIBUTION_POINTS;
			break;
		case NID_info_access:
			ret = Extension::AUTHORITY_INFORMATION_ACCESS;
			break;
		case NID_basic_constraints:
			ret = Extension::BASIC_CONSTRAINTS;
			break;
		case NID_certificate_policies:
			ret = Extension::CERTIFICATE_POLICIES;
			break;
		case NID_issuer_alt_name:
			ret = Extension::ISSUER_ALTERNATIVE_NAME;
			break;
		case NID_subject_alt_name:
			ret = Extension::SUBJECT_ALTERNATIVE_NAME;
			break;
		case NID_sinfo_access:
			ret = Extension::SUBJECT_INFORMATION_ACCESS;
			break;
		case NID_subject_key_identifier:
			ret = Extension::SUBJECT_KEY_IDENTIFIER;
			break;
		case NID_crl_number:
			ret = Extension::CRL_NUMBER;
			break;
		case NID_delta_crl:
			ret = Extension::DELTA_CRL_INDICATOR;
			break;			
		default:
			ret = Extension::UNKNOWN;
	}
	return ret;
}

Extension::Name Extension::getName(X509_EXTENSION *ext)
{
	int nid;
	nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
	return Extension::getName(nid);
}
