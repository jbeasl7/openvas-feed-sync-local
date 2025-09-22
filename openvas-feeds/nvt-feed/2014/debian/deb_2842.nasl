# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702842");
  script_cve_id("CVE-2013-4152", "CVE-2013-7315");
  script_tag(name:"creation_date", value:"2014-01-12 23:00:00 +0000 (Sun, 12 Jan 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2842-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2842-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2842-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2842");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspring-java' package(s) announced via the DSA-2842-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alvaro Munoz discovered a XML External Entity (XXE) injection in the Spring Framework which can be used for conducting CSRF and DoS attacks on other sites.

The Spring OXM wrapper did not expose any property for disabling entity resolution when using the JAXB unmarshaller. There are four possible source implementations passed to the unmarshaller:

DOMSource

StAXSource

SAXSource

StreamSource

For a DOMSource, the XML has already been parsed by user code and that code is responsible for protecting against XXE.

For a StAXSource, the XMLStreamReader has already been created by user code and that code is responsible for protecting against XXE.

For SAXSource and StreamSource instances, Spring processed external entities by default thereby creating this vulnerability.

The issue was resolved by disabling external entity processing by default and adding an option to enable it for those users that need to use this feature when processing XML from a trusted source.

It was also identified that Spring MVC processed user provided XML with JAXB in combination with a StAX XMLInputFactory without disabling external entity resolution. External entity resolution has been disabled in this case.

For the stable distribution (wheezy), this problem has been fixed in version 3.0.6.RELEASE-6+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 3.0.6.RELEASE-10.

We recommend that you upgrade your libspring-java packages.");

  script_tag(name:"affected", value:"'libspring-java' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libspring-aop-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-beans-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-core-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-expression-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jms-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-orm-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-test-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-struts-java", ver:"3.0.6.RELEASE-6+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
