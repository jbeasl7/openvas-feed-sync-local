# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7109.1");
  script_cve_id("CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725", "CVE-2023-24531", "CVE-2023-24536", "CVE-2023-29402", "CVE-2023-29403", "CVE-2023-29404", "CVE-2023-29405", "CVE-2023-29406", "CVE-2023-39318", "CVE-2023-39319", "CVE-2023-39323", "CVE-2023-39325", "CVE-2023-45288", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24785", "CVE-2024-24789", "CVE-2024-24790", "CVE-2024-24791", "CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_tag(name:"creation_date", value:"2024-11-15 04:08:07 +0000 (Fri, 15 Nov 2024)");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:59:12 +0000 (Tue, 18 Jun 2024)");

  script_name("Ubuntu: Security Advisory (USN-7109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7109-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7109-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.18' package(s) announced via the USN-7109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Philippe Antoine discovered that Go incorrectly handled crafted HTTP/2
streams. An attacker could possibly use this issue to cause a denial of
service. (CVE-2022-41723)

Marten Seemann discovered that Go did not properly manage memory under
certain circumstances. An attacker could possibly use this issue to cause
a panic resulting in a denial of service. (CVE-2022-41724)

Ameya Darshan and Jakob Ackermann discovered that Go did not properly
validate the amount of memory and disk files ReadForm can consume. An
attacker could possibly use this issue to cause a panic resulting in a
denial of service. (CVE-2022-41725)

Hunter Wittenborn discovered that Go incorrectly handled the sanitization
of environment variables. An attacker could possibly use this issue to run
arbitrary commands. (CVE-2023-24531)

Jakob Ackermann discovered that Go incorrectly handled multipart
forms. An attacker could possibly use this issue to consume an excessive
amount of resources, resulting in a denial of service. (CVE-2023-24536)

Juho Nurminen discovered that Go incorrectly handled certain special
characters in directory or file paths. An attacker could possibly use
this issue to inject code into the resulting binaries. (CVE-2023-29402)

Vincent Dehors discovered that Go incorrectly handled permission bits.
An attacker could possibly use this issue to read or write files with
elevated privileges. (CVE-2023-29403)

Juho Nurminen discovered that Go incorrectly handled certain compiler
directives. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2023-29404)

Juho Nurminen discovered that Go incorrectly handled certain crafted
arguments. An attacker could possibly use this issue to execute arbitrary
code at build time. (CVE-2023-29405)

Bartek Nowotarski discovered that Go incorrectly validated the contents of
host headers. A remote attacker could possibly use this issue to inject
additional headers or entire requests. (CVE-2023-29406)

Takeshi Kaneko discovered that Go did not properly handle comments and
special tags in the script context of html/template module. An attacker
could possibly use this issue to inject Javascript code and perform a
cross-site scripting attack. (CVE-2023-39318, CVE-2023-39319)

It was discovered that Go did not properly validate the '//go:cgo_'
directives during compilation. An attacker could possibly use this issue
to inject arbitrary code during compile time. (CVE-2023-39323)

It was discovered that Go did not limit the number of simultaneously
executing handler goroutines in the net/http module. An attacker could
possibly use this issue to cause a panic resulting in a denial of service.
(CVE-2023-39325)

Bartek Nowotarski was discovered that the Go net/http module did not
properly handle the requests when request's headers exceed MaxHeaderBytes.
An attacker could possibly use this issue to cause a panic resulting into
a denial of service. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'golang-1.18' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18", ver:"1.18.1-1ubuntu1~16.04.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-go", ver:"1.18.1-1ubuntu1~16.04.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-src", ver:"1.18.1-1ubuntu1~16.04.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18", ver:"1.18.1-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-go", ver:"1.18.1-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-src", ver:"1.18.1-1ubuntu1~18.04.4+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18", ver:"1.18.1-1ubuntu1~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-go", ver:"1.18.1-1ubuntu1~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-src", ver:"1.18.1-1ubuntu1~20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18", ver:"1.18.1-1ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-go", ver:"1.18.1-1ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.18-src", ver:"1.18.1-1ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
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
