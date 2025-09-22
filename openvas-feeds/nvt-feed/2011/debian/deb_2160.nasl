# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68994");
  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-0534");
  script_tag(name:"creation_date", value:"2011-03-07 15:04:02 +0000 (Mon, 07 Mar 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2160-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2160-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2160");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat6' package(s) announced via the DSA-2160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Tomcat Servlet and JSP engine:

CVE-2010-3718

It was discovered that the SecurityManager insufficiently restricted the working directory.

CVE-2011-0013

It was discovered that the HTML manager interface is affected by cross-site scripting.

CVE-2011-0534

It was discovered that NIO connector performs insufficient validation of the HTTP headers, which could lead to denial of service.

The oldstable distribution (lenny) is not affected by these issues.

For the stable distribution (squeeze), this problem has been fixed in version 6.0.28-9+squeeze1.

For the unstable distribution (sid), this problem has been fixed in version 6.0.28-10.

We recommend that you upgrade your tomcat6 packages.");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libservlet2.5-java", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libservlet2.5-java-doc", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat6-java", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-admin", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-common", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-docs", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-examples", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat6-user", ver:"6.0.28-9+squeeze1", rls:"DEB6"))) {
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
