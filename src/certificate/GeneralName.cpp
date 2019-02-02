#include <libcryptosec/certificate/GeneralName.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/CertificationException.h>

GeneralName::GeneralName()
{
	this->type = GeneralName::UNDEFINED;
}

GeneralName::GeneralName(const GENERAL_NAME* generalName)
{
	THROW_DECODE_ERROR_IF(generalName == NULL);

	std::string data;

	switch (generalName->type) {
		case GEN_OTHERNAME:
		{
			THROW_DECODE_ERROR_IF(generalName->d.otherName == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.otherName->value == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.otherName->value->type != V_ASN1_OCTET_STRING);
			// TODO: não suporta outros tipos?

			const ASN1_OCTET_STRING *octetString = generalName->d.otherName->value->value.octet_string;
			THROW_DECODE_ERROR_IF(octetString == NULL);
			THROW_DECODE_ERROR_IF(octetString->data == NULL);

			data.assign((const char *) octetString->data, octetString->length);

			ObjectIdentifier oid((const ASN1_OBJECT*) generalName->d.otherName->type_id);
			this->setOtherName(oid, data);
			break;
		}
		case GEN_EMAIL:
			THROW_DECODE_ERROR_IF(generalName->d.rfc822Name == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.rfc822Name->data == NULL);
			data = (char*) generalName->d.rfc822Name->data;
			this->setRfc822Name(data);
			break;
		case GEN_DNS:
			THROW_DECODE_ERROR_IF(generalName->d.dNSName == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.dNSName->data == NULL);
			data = (char*) (generalName->d.dNSName->data);
			this->setDnsName(data);
			break;
		case GEN_DIRNAME:
		{
			THROW_DECODE_ERROR_IF(generalName->d.directoryName == NULL);
			RDNSequence directoryName(generalName->d.directoryName);
			this->setDirectoryName(directoryName);
			break;
		}
		case GEN_IPADD:
			THROW_DECODE_ERROR_IF(generalName->d.iPAddress == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.iPAddress->data == NULL);
			data = GeneralName::data2IpAddress((const unsigned char *) (generalName->d.iPAddress->data));
			this->setIpAddress(data);
			break;
		case GEN_URI:
			THROW_DECODE_ERROR_IF(generalName->d.uniformResourceIdentifier == NULL);
			THROW_DECODE_ERROR_IF(generalName->d.uniformResourceIdentifier->data == NULL);
			data = (char *) (generalName->d.uniformResourceIdentifier->data);
			this->setUniformResourceIdentifier(data);
			break;
		case GEN_RID:
		{
			THROW_DECODE_ERROR_IF(generalName->d.registeredID == NULL);
			ObjectIdentifier registeredId((const ASN1_OBJECT*) generalName->d.registeredID);
			this->setRegisteredId(registeredId);
			break;
		}
		default:
			this->type = GeneralName::UNDEFINED;
			break;
	}
}

GeneralName::~GeneralName()
{
}

void GeneralName::setOtherName(const ObjectIdentifier& oid, const std::string& data) {
	this->clean();
	this->type = GeneralName::OTHER_NAME;
	this->oid = oid;
	this->data = data;
}

std::pair<ObjectIdentifier, std::string> GeneralName::getOtherName() const
{
	return std::pair<ObjectIdentifier, std::string>(this->oid, this->data);
}

void GeneralName::setRfc822Name(const std::string& rfc822Name)
{
	this->clean();
	this->type = GeneralName::RFC_822_NAME;
	this->data = rfc822Name;
}

const std::string& GeneralName::getRfc822Name() const
{
	return this->data;
}
 
void GeneralName::setDnsName(const std::string& dnsName)
{
	this->clean();
	this->type = GeneralName::DNS_NAME;
	this->data = dnsName;
}

const std::string& GeneralName::getDnsName() const
{
	return this->data;
}

void GeneralName::setUniformResourceIdentifier(const std::string& uniformResourceIdentifier)
{
	this->clean();
	this->type = GeneralName::UNIFORM_RESOURCE_IDENTIFIER;
	this->data = uniformResourceIdentifier;
}

void GeneralName::setIpAddress(const std::string& ipAddress)
{
	this->clean();
	this->type = GeneralName::IP_ADDRESS;
	this->data = ipAddress;
}

const std::string& GeneralName::getIpAddress() const
{
	return this->data;
}

const std::string& GeneralName::getUniformResourceIdentifier() const
{
	return this->data;
}

void GeneralName::setDirectoryName(const RDNSequence& directoryName)
{
	this->clean();
	this->type = GeneralName::DIRECTORY_NAME;
	this->directoryName = directoryName;
}

const RDNSequence& GeneralName::getDirectoryName() const
{
	return this->directoryName;
}

void GeneralName::setRegisteredId(const ObjectIdentifier& registeredId)
{
	this->clean();
	this->type = GeneralName::REGISTERED_ID;
	this->registeredId = registeredId;
}

const ObjectIdentifier& GeneralName::getRegisteredId() const
{
	return this->registeredId;
}

GeneralName::Type GeneralName::getType() const
{
	return this->type;
}

std::string GeneralName::toXml(const std::string& tab) const
{
	std::string ret, name;
	name = GeneralName::type2Name(this->type);
	ret = tab + "<" + name + ">\n";
	switch (this->type)
	{
		case GeneralName::OTHER_NAME:
			ret += tab + "\t" + this->oid.toString() + " : " + this->data + "\n";
			break;
		case GeneralName::RFC_822_NAME:
			ret += tab + "\t" + this->data + "\n";
			break;
		case GeneralName::DNS_NAME:
			ret += tab + "\t" + this->data + "\n";
			break;
		case GeneralName::DIRECTORY_NAME:
			ret += this->directoryName.toXml(tab + "\t");
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret += tab + "\t" + this->data + "\n";
			break;
		case GeneralName::IP_ADDRESS:
			ret += tab + "\t" + this->data + "\n";
			break;
		case GeneralName::REGISTERED_ID:
			ret += tab + "\t" + this->registeredId.getShortName() + "\n";
			break;
		default:
			break;
	}
	ret += tab + "</" + name + ">\n";
	return ret;
}

GENERAL_NAME* GeneralName::getSslObject() const
{
	GENERAL_NAME *ret;
	ASN1_TYPE *otherNameValue;
	unsigned char *ipAddress;
	int rc = 0;

	ret = GENERAL_NAME_new();
	THROW_ENCODE_ERROR_IF(ret == NULL);

	switch (this->type) {
		case GeneralName::OTHER_NAME:
			ret->type = GEN_OTHERNAME;
			ret->d.otherName = OTHERNAME_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.otherName == NULL,
					GENERAL_NAME_free(ret);
			);

			try {
				ret->d.otherName->type_id = this->oid.getSslObject();
			} catch (...) {
				GENERAL_NAME_free(ret);
				throw;
			}

			otherNameValue = ASN1_TYPE_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(otherNameValue == NULL,
					GENERAL_NAME_free(ret);
			);

			rc = ASN1_TYPE_set_octetstring(otherNameValue, (unsigned char*) this->data.c_str(), this->data.length());
			ASN1_TYPE_free(otherNameValue);
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					GENERAL_NAME_free(ret);
			);

			ret->d.otherName->value = otherNameValue;
			break;
		case GeneralName::RFC_822_NAME:
			ret->type = GEN_EMAIL;
			ret->d.rfc822Name = ASN1_IA5STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.rfc822Name == NULL,
					GENERAL_NAME_free(ret);
			);

			rc = ASN1_STRING_set(ret->d.rfc822Name, this->data.c_str(), this->data.size());
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					GENERAL_NAME_free(ret);
			);

			break;
		case GeneralName::DNS_NAME:
			ret->type = GEN_DNS;
			ret->d.dNSName = ASN1_IA5STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.rfc822Name == NULL,
					GENERAL_NAME_free(ret);
			);

			rc = ASN1_STRING_set(ret->d.dNSName, this->data.c_str(), this->data.size());
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					GENERAL_NAME_free(ret);
			);

			break;
		case GeneralName::DIRECTORY_NAME:
			ret->type = GEN_DIRNAME;
			try {
				ret->d.directoryName = this->directoryName.getSslObject();
			} catch (...) {
				GENERAL_NAME_free(ret);
				throw;
			}
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret->type = GEN_URI;
			ret->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.uniformResourceIdentifier == NULL,
					GENERAL_NAME_free(ret);
			);

			rc = ASN1_STRING_set(ret->d.uniformResourceIdentifier, this->data.c_str(), this->data.size());
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					GENERAL_NAME_free(ret);
			);

			break;
		case GeneralName::IP_ADDRESS:
			ret->type = GEN_IPADD;
			ret->d.iPAddress = ASN1_OCTET_STRING_new();
			THROW_ENCODE_ERROR_AND_FREE_IF(ret->d.uniformResourceIdentifier == NULL,
					GENERAL_NAME_free(ret);
			);

			ipAddress = GeneralName::ipAddress2Data(this->data);
			rc = ASN1_OCTET_STRING_set(ret->d.iPAddress, ipAddress, 4);
			delete ipAddress;
			THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
					GENERAL_NAME_free(ret);
			);

			break;
		case GeneralName::REGISTERED_ID:
			ret->type = GEN_RID;
			try {
				ret->d.registeredID = this->registeredId.getSslObject();
			} catch (...) {
				GENERAL_NAME_free(ret);
				throw;
			}
			break;
		case GeneralName::UNDEFINED:
			// TODO: não deveria lançar uma exceção?
			break;
	}
	return ret;
}



std::string GeneralName::type2Name(GeneralName::Type type)
{
	std::string ret;
	switch (type)
	{
		case GeneralName::OTHER_NAME:
			ret = "otherName";
			break;
		case GeneralName::RFC_822_NAME:
			ret = "rfc822Name";
			break;
		case GeneralName::DNS_NAME:
			ret = "dnsName";
			break;
		case GeneralName::DIRECTORY_NAME:
			ret = "directoryName";
			break;
		case GeneralName::UNIFORM_RESOURCE_IDENTIFIER:
			ret = "uniformResourceIdentifier";
			break;
		case GeneralName::IP_ADDRESS:
			ret = "iPAddress";
			break;
		case GeneralName::REGISTERED_ID:
			ret = "registeredID";
			break;
		default:
			ret = "undefined";
			break;
	}
	return ret;
}

std::string GeneralName::data2IpAddress(const unsigned char *data)
{
	std::stringstream ss;
	std::string temp;
	int value = data[0];
	std::string ret = ss.str();
	for (int i = 1; i < 4; i++) {
		value = data[i];
		ss.clear();
		ss << value;
		ret += ".";
		ret += ss.str();
	}
	return ret;
}

unsigned char* GeneralName::ipAddress2Data(const std::string& ipAddress)
{
	THROW_DECODE_ERROR_IF(ipAddress.size() > (4 * 3 + 3));
	THROW_DECODE_ERROR_IF(ipAddress.size() < (4 + 3));

	size_t firstPoint = ipAddress.find(".", 0);
	THROW_DECODE_ERROR_IF(firstPoint == std::string::npos);
	THROW_DECODE_ERROR_IF(firstPoint == 0);
	THROW_DECODE_ERROR_IF(firstPoint > 3);

	size_t secondPoint = ipAddress.find(".", firstPoint + 1);
	THROW_DECODE_ERROR_IF(secondPoint == std::string::npos);
	THROW_DECODE_ERROR_IF(secondPoint == firstPoint + 1);
	THROW_DECODE_ERROR_IF(secondPoint > firstPoint + 4);

	size_t thirdPoint = ipAddress.find(".", secondPoint + 1);
	THROW_DECODE_ERROR_IF(thirdPoint == std::string::npos);
	THROW_DECODE_ERROR_IF(thirdPoint == secondPoint + 1);
	THROW_DECODE_ERROR_IF(thirdPoint > secondPoint + 4);

	std::string firstOctet = ipAddress.substr(0, firstPoint);
	std::string secondOctet = ipAddress.substr(firstPoint + 1, secondPoint - firstPoint - 1);
	std::string thirdOctet = ipAddress.substr(secondPoint + 1, thirdPoint - secondPoint - 1);
	std::string fourthOctet = ipAddress.substr(thirdPoint + 1, ipAddress.size() - thirdPoint - 1);

	unsigned char *ret = new unsigned char[5];
	ret[0] = std::stoi(firstOctet);
	ret[1] = std::stoi(secondOctet);
	ret[2] = std::stoi(thirdOctet);
	ret[3] = std::stoi(fourthOctet);
	ret[4] = 0x00;

	return ret;
}

void GeneralName::clean()
{
	this->oid = ObjectIdentifier();
	this->data.clear();
	this->directoryName = RDNSequence();
	this->registeredId = ObjectIdentifier();
}

