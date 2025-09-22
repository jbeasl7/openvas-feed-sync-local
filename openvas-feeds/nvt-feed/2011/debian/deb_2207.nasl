# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69417");
  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2010-07-13 22:29:00 +0000 (Tue, 13 Jul 2010)");

  script_name("Debian: Security Advisory (DSA-2207-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2207-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2207-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2207");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat5.5' package(s) announced via the DSA-2207-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various vulnerabilities have been discovered in the Tomcat Servlet and JSP engine, resulting in denial of service, cross-site scripting, information disclosure and WAR file traversal. Further details on the individual security issues can be found on the Apache Tomcat 5 vulnerabilities page.

For the oldstable distribution (lenny), this problem has been fixed in version 5.5.26-5lenny2.

The stable distribution (squeeze) no longer contains tomcat5.5. tomcat6 is already fixed.

The unstable distribution (sid) no longer contains tomcat5.5. tomcat6 is already fixed.

We recommend that you upgrade your tomcat5.5 packages.");

  script_tag(name:"affected", value:"'tomcat5.5' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat5.5-java", ver:"5.5.26-5lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat5.5", ver:"5.5.26-5lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat5.5-admin", ver:"5.5.26-5lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat5.5-webapps", ver:"5.5.26-5lenny2", rls:"DEB5"))) {
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
