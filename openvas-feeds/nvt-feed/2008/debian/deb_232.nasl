# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53327");
  script_version("2024-09-10T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-09-10 05:05:42 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2004-01-01 05:00:00 +0000 (Thu, 01 Jan 2004)");
  script_name("Debian Security Advisory DSA 232-2 (cupsys)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20232-2");
  script_tag(name:"insight", value:"This update corrects a library dependency for the libcupsys2 package
which sneaked in with the last security update to CUPS for the stable
distribution (woody).

The original advisory DSA 232-1 stated:

Multiple vulnerabilities were discovered in the Common Unix
Printing System (CUPS).  Several of these issues represent the
potential for a remote compromise or denial of service.  The Common
Vulnerabilities and Exposures project identifies the problems
listed above.");
  script_tag(name:"summary", value:"The remote host is missing an update to cupsys
announced via advisory DSA 232-2.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cupsys", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cupsys-pstoraster", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.1.14-4.4", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
