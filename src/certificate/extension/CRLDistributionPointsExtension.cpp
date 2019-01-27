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
	THROW_EXTENSION_DECODE_IF(this->getName() != Extension::CRL_DISTRIBUTION_POINTS);

	CRL_DIST_POINTS *sslObjectStack = (CRL_DIST_POINTS*) X509V3_EXT_d2i((X509_EXTENSION*) ext);
	THROW_EXTENSION_DECODE_IF(sslObjectStack == NULL);

	int num = sk_DIST_POINT_num(sslObjectStack);
	for (int i = 0; i < num; i++) {
		DIST_POINT *sslObject = (DIST_POINT*) sk_DIST_POINT_value(sslObjectStack, i);
		THROW_EXTENSION_DECODE_AND_FREE_IF(sslObject == NULL,
				CRL_DIST_POINTS_free(sslObjectStack);
		);

		try {
			DistributionPoint distPoint(sslObject);
			this->distributionPoints.push_back(std::move(distPoint));
		} catch (...) {
			CRL_DIST_POINTS_free(sslObjectStack);
			throw;
		}
	}

	CRL_DIST_POINTS_free(sslObjectStack);
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
	THROW_EXTENSION_ENCODE_IF(distPoints == NULL);

	for (auto distributionPoint : this->distributionPoints) {
		DIST_POINT *sslObject = NULL;

		try {
			sslObject = distributionPoint.getDistPoint();
		} catch (...) {
			CRL_DIST_POINTS_free(distPoints);
			throw;
		}

		int rc = sk_DIST_POINT_push(distPoints, sslObject);
		THROW_EXTENSION_ENCODE_AND_FREE_IF(rc == 0,
				DIST_POINT_free(sslObject);
				CRL_DIST_POINTS_free(distPoints);
		);
	}

	X509_EXTENSION *ret = X509V3_EXT_i2d(NID_crl_distribution_points, this->critical ? 1 : 0, (void*) distPoints);
	CRL_DIST_POINTS_free(distPoints);
	THROW_EXTENSION_ENCODE_IF(ret == NULL);

	return ret;
}
