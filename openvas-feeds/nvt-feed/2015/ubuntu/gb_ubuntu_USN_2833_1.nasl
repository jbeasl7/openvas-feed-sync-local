# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842560");
  script_cve_id("CVE-2015-7201", "CVE-2015-7202", "CVE-2015-7203", "CVE-2015-7204", "CVE-2015-7205", "CVE-2015-7207", "CVE-2015-7208", "CVE-2015-7210", "CVE-2015-7211", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214", "CVE-2015-7215", "CVE-2015-7216", "CVE-2015-7217", "CVE-2015-7218", "CVE-2015-7219", "CVE-2015-7220", "CVE-2015-7221", "CVE-2015-7222", "CVE-2015-7223");
  script_tag(name:"creation_date", value:"2015-12-16 04:50:34 +0000 (Wed, 16 Dec 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2833-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2833-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrei Vaida, Jesse Ruderman, Bob Clary, Christian Holler, Jesse Ruderman,
Eric Rahm, Robert Kaiser, Harald Kirschner, and Michael Henretty
discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2015-7201, CVE-2015-7202)

Ronald Crane discovered three buffer overflows through code inspection.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit these to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2015-7203, CVE-2015-7220, CVE-2015-7221)

Cajus Pollmeier discovered a crash during javascript variable assignments
in some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Firefox.
(CVE-2015-7204)

Ronald Crane discovered a buffer overflow through code inspection. If a
user were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2015-7205)

It was discovered that it is possible to read cross-origin URLs following
a redirect if performance.getEntries() is used with an iframe to host a
page. If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same-origin
restrictions. (CVE-2015-7207)

It was discovered that Firefox allows for control characters to be set in
cookies. An attacker could potentially exploit this to conduct cookie
injection attacks on some web servers. (CVE-2015-7208)

Looben Yang discovered a use-after-free in WebRTC when closing channels in
some circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2015-7210)

Abdulrahman Alqabandi discovered that hash symbol is incorrectly handled
when parsing data: URLs. An attacker could potentially exploit this to
conduct URL spoofing attacks. (CVE-2015-7211)

Abhishek Arya discovered an integer overflow when allocating large
textures. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial of
service via application crash, or execute arbitrary code with the
privileges of the user invoking Firefox. (CVE-2015-7212)

Ronald Crane discovered an integer overflow when processing MP4 format
video in some circumstances. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"43.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"43.0+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"43.0+build1-0ubuntu0.15.04.1", rls:"UBUNTU15.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"43.0+build1-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
