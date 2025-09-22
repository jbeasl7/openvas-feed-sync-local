# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702890");
  script_cve_id("CVE-2014-0054", "CVE-2014-1904");
  script_tag(name:"creation_date", value:"2014-03-28 23:00:00 +0000 (Fri, 28 Mar 2014)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-2890-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2890-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2890");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libspring-java' package(s) announced via the DSA-2890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in libspring-java, the Debian package for the Java Spring framework.

CVE-2014-0054

Jaxb2RootElementHttpMessageConverter in Spring MVC processes external XML entities.

CVE-2014-1904

Spring MVC introduces a cross-site scripting vulnerability if the action on a Spring form is not specified.

For the stable distribution (wheezy), these problems have been fixed in version 3.0.6.RELEASE-6+deb7u3.

For the testing distribution (jessie) and the unstable distribution (sid), these problems have been fixed in version 3.0.6.RELEASE-13.

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

  if(!isnull(res = isdpkgvuln(pkg:"libspring-aop-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-beans-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-context-support-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-core-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-expression-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-instrument-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jdbc-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-jms-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-orm-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-oxm-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-test-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-transaction-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-portlet-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-servlet-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libspring-web-struts-java", ver:"3.0.6.RELEASE-6+deb7u3", rls:"DEB7"))) {
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
