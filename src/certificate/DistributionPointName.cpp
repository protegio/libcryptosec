#include <libcryptosec/certificate/DistributionPointName.h>

#include <libcryptosec/Macros.h>
#include <libcryptosec/exception/DecodeException.h>
#include <libcryptosec/exception/EncodeException.h>

DistributionPointName::DistributionPointName()
{
	this->type = DistributionPointName::UNDEFINED;
}

DistributionPointName::DistributionPointName(const DIST_POINT_NAME *dpn)
{
	THROW_DECODE_ERROR_IF(dpn == NULL);

	switch (dpn->type)
	{
		case 0:
			this->type = DistributionPointName::FULL_NAME;
			this->fullName = GeneralNames(dpn->name.fullname);
			break;
		case 1:
			this->type = DistributionPointName::RELATIVE_NAME;
			this->relativeName = RDNSequence(dpn->name.relativename);
			break;
		default:
			this->type = DistributionPointName::UNDEFINED;
			break;
	}
}

DistributionPointName::~DistributionPointName()
{
}

void DistributionPointName::setNameRelativeToCrlIssuer(const RDNSequence& rdnSequence)
{
	this->type = DistributionPointName::RELATIVE_NAME;
	this->relativeName = rdnSequence;
	this->fullName = GeneralNames();
}

const RDNSequence& DistributionPointName::getNameRelativeToCrlIssuer() const
{
	return this->relativeName;
}

void DistributionPointName::setFullName(const GeneralNames& generalNames)
{
	this->type = DistributionPointName::FULL_NAME;
	this->fullName = generalNames;
	this->relativeName = RDNSequence();
}

const GeneralNames& DistributionPointName::getFullName() const
{
	return this->fullName;
}

DistributionPointName::Type DistributionPointName::getType() const
{
	return this->type;
}

std::string DistributionPointName::toXml(const std::string& tab) const
{
	std::string ret = tab + "<distributionPointName>\n";
	switch (this->type)
	{
		case DistributionPointName::FULL_NAME:
			ret += this->fullName.toXml(tab + "\t");
			break;
		case DistributionPointName::RELATIVE_NAME:
			ret += this->relativeName.toXml(tab + "\t");
			break;
		default:
			ret += tab + "\tundefined\n";
			break;
	}
	ret += tab + "</distributionPointName>\n";
	return ret;
}

DIST_POINT_NAME* DistributionPointName::getSslObject() const
{
	DIST_POINT_NAME *ret;
	X509_NAME *name;
	ret = DIST_POINT_NAME_new();
	switch (this->type)
	{
		case DistributionPointName::FULL_NAME:
			ret->type = 0;
			ret->name.fullname = this->fullName.getSslObject();
			break;
		case DistributionPointName::RELATIVE_NAME:
			ret->type = 1;
			name = this->relativeName.getSslObject();
			DIST_POINT_set_dpname(ret, name);
			X509_NAME_free(name);
			break;
		default:
			ret->type = -1;
			break;
	}
	return ret;
}
