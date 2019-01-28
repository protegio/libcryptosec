#include <libcryptosec/certificate/GeneralNames.h>

GeneralNames::GeneralNames()
{
}

GeneralNames::GeneralNames(GENERAL_NAMES *generalNames)
{
	int i, num;
	GENERAL_NAME *value;
	std::string data, oid;
	RDNSequence directoryName;
	ObjectIdentifier registeredId;
	num = sk_GENERAL_NAME_num(generalNames);
	if (generalNames)
	{
		for (i=0;i<num;i++)
		{
			value = sk_GENERAL_NAME_value(generalNames, i);
			GeneralName generalName(value);
			this->generalNames.push_back(generalName);
		}
	}
}

//GeneralNames::GeneralNames(const GeneralNames& gns)
//{
//	this->generalNames = sk_GENERAL_NAME_dup(gns.getGeneralNames());
//}

GeneralNames::~GeneralNames()
{
}

std::string GeneralNames::getXmlEncoded(const std::string& tab) const
{
	std::string ret;
	ret += tab + "<generalNames>\n";
	for (auto generalName : this->generalNames) {
		ret += generalName.getXmlEncoded(tab + "\t");
	}
	ret += tab + "</generalNames>\n";
	return ret;
}

void GeneralNames::addGeneralName(GeneralName &generalName)
{
	this->generalNames.push_back(generalName);
}

std::vector<GeneralName> GeneralNames::getGeneralNames() const
{
	return this->generalNames;
}

int GeneralNames::getNumberOfEntries() const
{
	return this->generalNames.size();
}

GENERAL_NAMES* GeneralNames::getInternalGeneralNames() const
{
	GENERAL_NAMES *sslObjectStack = GENERAL_NAMES_new();
	for (auto generalName : this->generalNames)
	{
		GENERAL_NAME *sslObject = generalName.getSslObject();
		sk_GENERAL_NAME_push(sslObjectStack, sslObject);
	}
	return sslObjectStack;
}

/**
 * @deprecated Método movido para a classe GeneralName. Futuramente poderá ser removido dessa classe.
 */
std::string GeneralNames::data2IpAddress(unsigned char *data)
{
	return GeneralName::data2IpAddress(data);
}

GeneralNames& GeneralNames::operator=(const GeneralNames& value)
{
	this->generalNames = value.getGeneralNames(); 
	return *this;
}
