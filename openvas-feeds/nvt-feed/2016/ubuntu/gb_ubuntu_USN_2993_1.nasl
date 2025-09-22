# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842785");
  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2825", "CVE-2016-2828", "CVE-2016-2829", "CVE-2016-2831", "CVE-2016-2832", "CVE-2016-2833", "CVE-2016-2834");
  script_tag(name:"creation_date", value:"2016-06-10 03:23:29 +0000 (Fri, 10 Jun 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-13 15:49:48 +0000 (Mon, 13 Jun 2016)");

  script_name("Ubuntu: Security Advisory (USN-2993-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2993-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2993-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2993-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Holler, Gary Kwong, Jesse Ruderman, Tyson Smith, Timothy Nikkel,
Sylvestre Ledru, Julian Seward, Olli Pettay, Karl Tomlinson, Christoph
Diehl, Julian Hector, Jan de Mooij, Mats Palmgren, and Tooru Fujisawa
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-2815, CVE-2016-2818)

A buffer overflow was discovered when parsing HTML5 fragments in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2819)

A use-after-free was discovered in contenteditable mode in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2821)

Jordi Chancel discovered a way to use a persistent menu within a <select>
element and place this in an arbitrary location. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to spoof the addressbar contents. (CVE-2016-2822)

Armin Razmdjou that the location.host property can be set to an arbitrary
string after creating an invalid data: URI. If a user were tricked in to
opening a specially crafted website, an attacker could potentially exploit
this to bypass some same-origin protections. (CVE-2016-2825)

A use-after-free was discovered when processing WebGL content in some
circumstances. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code. (CVE-2016-2828)

Tim McCormack discovered that the permissions notification can show the
wrong icon when a page requests several permissions in quick succession.
An attacker could potentially exploit this by tricking the user in to
giving consent for access to the wrong resource. (CVE-2016-2829)

It was discovered that a pointerlock can be created in a fullscreen
window without user consent in some circumstances, and this pointerlock
cannot be cancelled without quitting Firefox. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service or conduct clickjacking attacks.
(CVE-2016-2831)

John Schoenick discovered that CSS pseudo-classes can leak information
about plugins that are installed but disabled. An attacker could
potentially exploit this to fingerprint users. (CVE-2016-2832)

Matt Wobensmith discovered that Content Security Policy (CSP) does not
block the loading of cross-domain Java applets when specified by policy.
An ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"47.0+build3-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
