#include <libcryptosec/certificate/extension/CRLDistributionPointsExtension.h>

#include <libcryptosec/certificate/ObjectIdentifierFactory.h>
#include <libcryptosec/exception/CertificationException.h>

CRLDistributionPointsExtension::CRLDistributionPointsExtension() :
		Extension()
{
	this->objectIdentifier = ObjectIdentifierFactory::getObjectIdentifier(NID_crl_distribution_points);
}

CRLDistributionPointsExtension::CRLDistributionPointsExtension(const X509_EXTENSION *ext) :
		Extension(ext)
{
	ASN1_OBJECT* object = X509_EXTENSION_get_object((X509_EXTENSION*) ext);
	if (object == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int nid = OBJ_obj2nid(object);
	if (nid != NID_crl_distribution_points) {
		throw CertificationException(CertificationException::INVALID_TYPE, "CRLDistributionPointsExtension::CRLDistributionPointsExtension");
	}

	CRL_DIST_POINTS *points = (CRL_DIST_POINTS*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	if (points == NULL) {
		throw CertificationException("" /* TODO */);
	}

	int num = sk_DIST_POINT_num(points);
	for (int i = 0; i < num; i++) {
		DistributionPoint distPoint((DIST_POINT*) sk_DIST_POINT_value(points, i));
		this->distributionPoints.push_back(std::move(distPoint));
	}

	CRL_DIST_POINTS_free(points);
}

CRLDistributionPointsExtension::~CRLDistributionPointsExtension()
{
}

void CRLDistributionPointsExtension::addDistributionPoint(const DistributionPoint& distributionPoint)
{
	this->distributionPoints.push_back(distributionPoint);
}

const std::vector<DistributionPoint>& CRLDistributionPointsExtension::getDistributionPoints() const
{
	return this->distributionPoints;
}

std::string CRLDistributionPointsExtension::getXmlEncoded(const std::string& tab) const
{
	std::string ret, string;
	ret = tab + "<CRLDistributionPoints>\n";
		ret += tab + "\t<extnID>" + this->getName() + "</extnID>\n";
		string = (this->isCritical())?"yes":"no";
		ret += tab + "\t<critical>" + string + "</critical>\n";
		ret += tab + "\t<extnValue>\n";
			ret += tab + "\t\t<distributionPoints>\n";
			for (auto distributionPoint : this->distributionPoints) {
				string = distributionPoint.getXmlEncoded("\t\t\t");
				ret += tab + string;
			}
			ret += tab + "\t\t</distributionPoints>\n";
		ret += tab + "\t</extnValue>\n";
	ret += tab + "</CRLDistributionPoints>\n";
	return ret;
}

std::string CRLDistributionPointsExtension::extValue2Xml(const std::string& tab) const
{
	std::string ret, string;
	ret += tab + "<distributionPoints>\n";
	for (auto distributionPoint : this->distributionPoints) {
		string = distributionPoint.getXmlEncoded(tab + "\t");
		ret += string;
	}
	ret += tab + "</distributionPoints>\n";
	return ret;
}

X509_EXTENSION* CRLDistributionPointsExtension::getX509Extension() const
{
	CRL_DIST_POINTS *distPoints = CRL_DIST_POINTS_new();
	for (auto distributionPoint : this->distributionPoints) {
		sk_DIST_POINT_push(distPoints, distributionPoint.getDistPoint());
	}
	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_crl_distribution_points, this->critical ? 1 : 0, (void*) distPoints);
	CRL_DIST_POINTS_free(distPoints);
	return ret;
}
