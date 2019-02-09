#include <libcryptosec/certificate/GeneralNames.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

GeneralNames::GeneralNames()
{
}

GeneralNames::GeneralNames(const GENERAL_NAMES* generalNames)
{
	THROW_DECODE_ERROR_IF(generalNames == NULL);

	int num = sk_GENERAL_NAME_num(generalNames);
	for (int i = 0; i < num; i++) {
		const GENERAL_NAME *value = sk_GENERAL_NAME_value(generalNames, i);
		THROW_DECODE_ERROR_IF(value == NULL);
		GeneralName generalName(value);
		this->generalNames.push_back(std::move(generalName));
	}
}

GeneralNames::~GeneralNames()
{
}

void GeneralNames::addGeneralName(const GeneralName& generalName)
{
	this->generalNames.push_back(generalName);
}

const std::vector<GeneralName>& GeneralNames::getGeneralNames() const
{
	return this->generalNames;
}

int GeneralNames::getNumberOfEntries() const
{
	return this->generalNames.size();
}

std::string GeneralNames::toXml(const std::string& tab) const
{
	std::string ret;
	ret += tab + "<generalNames>\n";
	for (auto generalName : this->generalNames) {
		ret += generalName.toXml(tab + "\t");
	}
	ret += tab + "</generalNames>\n";
	return ret;
}

GENERAL_NAMES* GeneralNames::getSslObject() const
{
	GENERAL_NAMES *sslObjectStack = GENERAL_NAMES_new();
	THROW_ENCODE_ERROR_IF(sslObjectStack == NULL);

	for (auto generalName : this->generalNames) {
		GENERAL_NAME *sslObject = NULL;

		try {
			sslObject = generalName.getSslObject();
		} catch (...) {
			GENERAL_NAMES_free(sslObjectStack);
			throw;
		}

		int rc = sk_GENERAL_NAME_push(sslObjectStack, sslObject);
		THROW_ENCODE_ERROR_AND_FREE_IF(rc == 0,
				GENERAL_NAMES_free(sslObjectStack);
				GENERAL_NAME_free(sslObject);
		);
	}

	return sslObjectStack;
}
