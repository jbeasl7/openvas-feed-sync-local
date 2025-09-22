# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841802");
  script_cve_id("CVE-2014-1492", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1528", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532");
  script_tag(name:"creation_date", value:"2014-05-05 05:55:24 +0000 (Mon, 05 May 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-04-30 17:51:26 +0000 (Wed, 30 Apr 2014)");

  script_name("Ubuntu: Security Advisory (USN-2185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2185-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2185-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1313464");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2185-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bobby Holley, Carsten Book, Christoph Diehl, Gary Kwong, Jan de Mooij,
Jesse Ruderman, Nathan Froyd, John Schoenick, Karl Tomlinson, Vladimir
Vukicevic and Christian Holler discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1518, CVE-2014-1519)

An out of bounds read was discovered in Web Audio. An attacker could
potentially exploit this cause a denial of service via application crash
or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1522)

Abhishek Arya discovered an out of bounds read when decoding JPG images.
An attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2014-1523)

Abhishek Arya discovered a buffer overflow when a script uses a non-XBL
object as an XBL object. An attacker could potentially exploit this to
execute arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1524)

Abhishek Arya discovered a use-after-free in the Text Track Manager when
processing HTML video. An attacker could potentially exploit this to cause
a denial of service via application crash or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2014-1525)

Jukka Jylanki discovered an out-of-bounds write in Cairo when working
with canvas in some circumstances. An attacker could potentially exploit
this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2014-1528)

Mariusz Mlynski discovered that sites with notification permissions can
run script in a privileged context in some circumstances. An attacker
could exploit this to execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2014-1529)

It was discovered that browser history navigations could be used to load
a site with the addressbar displaying the wrong address. An attacker could
potentially exploit this to conduct cross-site scripting or phishing
attacks. (CVE-2014-1530)

A use-after-free was discovered when resizing images in some
circumstances. An attacker could potentially exploit this to cause a
denial of service via application crash or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2014-1531)

Christian Heimes discovered that NSS did not handle IDNA domain prefixes
correctly for wildcard certificates. An attacker could potentially exploit
this by using a specially crafted certificate to conduct a machine-in-the-middle
attack. (CVE-2014-1492)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free during
host resolution in some circumstances. An attacker could potentially
exploit this to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.12.10.3", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.13.10.3", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"29.0+build1-0ubuntu0.14.04.2", rls:"UBUNTU14.04 LTS"))) {
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
