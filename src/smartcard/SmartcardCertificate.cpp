#include <libcryptosec/smartcard/SmartcardCertificate.h>

SmartcardCertificate::SmartcardCertificate(std::string &id, std::string &label, std::string &serial, X509 *cert)
{
	this->id = id;
	this->label = label;
	this->serial = serial;
	this->cert = cert;
}

SmartcardCertificate::~SmartcardCertificate()
{
	X509_free(this->cert);
}

std::string SmartcardCertificate::getId()
{
	return this->id;
}

std::string SmartcardCertificate::getLabel()
{
	return this->label;
}

std::string SmartcardCertificate::getSerial()
{
	return this->serial;
}

Certificate* SmartcardCertificate::getCertificate()
{
	Certificate *ret = new Certificate((const X509*) this->cert);
	return ret;
}
