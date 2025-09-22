# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840465");
  script_cve_id("CVE-2008-5913", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1214");
  script_tag(name:"creation_date", value:"2010-07-26 14:14:51 +0000 (Mon, 26 Jul 2010)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:10:03 +0000 (Fri, 02 Feb 2024)");

  script_name("Ubuntu: Security Advisory (USN-930-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-930-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-930-5");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/599954");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ant, apturl, epiphany-browser, gluezilla, gnome-python-extras, liferea, mozvoikko, openjdk-6, packagekit, ubufox, webfav, yelp' package(s) announced via the USN-930-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-930-4 fixed vulnerabilities in Firefox and Xulrunner on Ubuntu 9.04 and
9.10. This update provides updated packages for use with Firefox 3.6 and
Xulrunner 1.9.2.

Original advisory details:

 If was discovered that Firefox could be made to access freed memory. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. This issue only affected
 Ubuntu 8.04 LTS. (CVE-2010-1121)

 Several flaws were discovered in the browser engine of Firefox. If a
 user were tricked into viewing a malicious site, a remote attacker could
 cause a denial of service or possibly execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2010-1200, CVE-2010-1201,
 CVE-2010-1202, CVE-2010-1203)

 A flaw was discovered in the way plugin instances interacted. An attacker
 could potentially exploit this and use one plugin to access freed memory from a
 second plugin to execute arbitrary code with the privileges of the user
 invoking the program. (CVE-2010-1198)

 An integer overflow was discovered in Firefox. If a user were tricked into
 viewing a malicious site, an attacker could overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1196)

 Martin Barbella discovered an integer overflow in an XSLT node sorting
 routine. An attacker could exploit this to overflow a buffer and cause a
 denial of service or possibly execute arbitrary code with the privileges of
 the user invoking the program. (CVE-2010-1199)

 Michal Zalewski discovered that the focus behavior of Firefox could be
 subverted. If a user were tricked into viewing a malicious site, a remote
 attacker could use this to capture keystrokes. (CVE-2010-1125)

 Ilja van Sprundel discovered that the 'Content-Disposition: attachment'
 HTTP header was ignored when 'Content-Type: multipart' was also present.
 Under certain circumstances, this could potentially lead to cross-site
 scripting attacks. (CVE-2010-1197)

 Amit Klein discovered that Firefox did not seed its random number generator
 often enough. An attacker could exploit this to identify and track users
 across different web sites. (CVE-2008-5913)

 Several flaws were discovered in the browser engine of Firefox. If a user
 were tricked into viewing a malicious site, a remote attacker could use
 this to crash the browser or possibly run arbitrary code as the user
 invoking the program. (CVE-2010-1208, CVE-2010-1209, CVE-2010-1211,
 CVE-2010-1212)

 An integer overflow was discovered in how Firefox processed plugin
 parameters. An attacker could exploit this to crash the browser or possibly
 run arbitrary code as the user invoking the program. (CVE-2010-1214)

 A flaw was discovered in the Firefox JavaScript engine. If a user were
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ant, apturl, epiphany-browser, gluezilla, gnome-python-extras, liferea, mozvoikko, openjdk-6, packagekit, ubufox, webfav, yelp' package(s) on Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ant", ver:"1.7.1-0ubuntu2.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"apturl", ver:"0.3.3ubuntu1.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"epiphany-browser", ver:"2.26.1-0ubuntu1.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8-4ubuntu3~9.04.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgluezilla", ver:"2.0-1ubuntu1.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liferea", ver:"1.4.26-0ubuntu1.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-packagekit", ver:"0.3.14-0ubuntu5.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozvoikko", ver:"0.9.5-1ubuntu2.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-gnome2-extras", ver:"2.19.1-0ubuntu14.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ubufox", ver:"0.9~rc2-0ubuntu0.9.04.2", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webfav", ver:"1.11-0ubuntu1.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"yelp", ver:"2.25.1-0ubuntu5.9.04.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ant", ver:"1.7.1-4ubuntu0.2", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b18-1.8-4ubuntu3~9.10.2", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozvoikko", ver:"1.0-1ubuntu3.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-gtkmozembed", ver:"2.25.3-3ubuntu1.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ubufox", ver:"0.9~rc2-0ubuntu0.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"webfav", ver:"1.16-0ubuntu1.9.10.1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"yelp", ver:"2.28.0-0ubuntu2.9.10.1", rls:"UBUNTU9.10"))) {
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
