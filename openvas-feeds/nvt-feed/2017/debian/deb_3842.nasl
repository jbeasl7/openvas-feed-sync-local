# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703842");
  script_cve_id("CVE-2017-5647", "CVE-2017-5648");
  script_tag(name:"creation_date", value:"2017-05-02 22:00:00 +0000 (Tue, 02 May 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-21 14:20:13 +0000 (Fri, 21 Apr 2017)");

  script_name("Debian: Security Advisory (DSA-3842-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3842-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3842-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3842");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat7' package(s) announced via the DSA-3842-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in tomcat7, a servlet and JSP engine.

CVE-2017-5647

Pipelined requests were processed incorrectly, which could result in some responses appearing to be sent for the wrong request.

CVE-2017-5648

Some application listeners calls were issued against the wrong objects, allowing untrusted applications running under a SecurityManager to bypass that protection mechanism and access or modify information associated with other web applications.

For the stable distribution (jessie), these problems have been fixed in version 7.0.56-3+deb8u10.

For the upcoming stable (stretch) and unstable (sid) distributions, these problems have been fixed in version 7.0.72-3.

We recommend that you upgrade your tomcat7 packages.");

  script_tag(name:"affected", value:"'tomcat7' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libservlet3.0-java-doc", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtomcat7-java", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-admin", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-common", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-docs", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-examples", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tomcat7-user", ver:"7.0.56-3+deb8u10", rls:"DEB8"))) {
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
