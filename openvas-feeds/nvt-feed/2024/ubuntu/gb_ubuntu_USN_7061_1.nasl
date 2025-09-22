# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7061.1");
  script_cve_id("CVE-2023-24531", "CVE-2023-24538", "CVE-2023-29402", "CVE-2023-29403", "CVE-2023-29404", "CVE-2023-29405", "CVE-2023-29406", "CVE-2023-39318", "CVE-2023-39319", "CVE-2023-39325", "CVE-2024-24785");
  script_tag(name:"creation_date", value:"2024-10-11 04:08:02 +0000 (Fri, 11 Oct 2024)");
  script_version("2024-10-11T15:39:44+0000");
  script_tag(name:"last_modification", value:"2024-10-11 15:39:44 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-16 13:15:55 +0000 (Fri, 16 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-7061-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7061-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7061-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.17' package(s) announced via the USN-7061-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hunter Wittenborn discovered that Go incorrectly handled the sanitization
of environment variables. An attacker could possibly use this issue to run
arbitrary commands. (CVE-2023-24531)

Sohom Datta discovered that Go did not properly validate backticks (`) as
Javascript string delimiters, and did not escape them as expected. An
attacker could possibly use this issue to inject arbitrary Javascript code
into the Go template. (CVE-2023-24538)

Juho Nurminen discovered that Go incorrectly handled certain special
characters in directory or file paths. An attacker could possibly use
this issue to inject code into the resulting binaries. (CVE-2023-29402)

Vincent Dehors discovered that Go incorrectly handled permission bits.
An attacker could possibly use this issue to read or write files with
elevated privileges. (CVE-2023-29403)

Juho Nurminen discovered that Go incorrectly handled certain crafted
arguments. An attacker could possibly use this issue to execute arbitrary
code at build time. (CVE-2023-29405)

It was discovered that Go incorrectly validated the contents of host
headers. A remote attacker could possibly use this issue to inject
additional headers or entire requests. (CVE-2023-29406)

Takeshi Kaneko discovered that Go did not properly handle comments and
special tags in the script context of html/template module. An attacker
could possibly use this issue to inject Javascript code and perform a
cross-site scripting attack. (CVE-2023-39318, CVE-2023-39319)

It was discovered that Go did not limit the number of simultaneously
executing handler goroutines in the net/http module. An attacker could
possibly use this issue to cause a panic resulting in a denial of service.
(CVE-2023-39325)

It was discovered that the Go html/template module did not validate errors
returned from MarshalJSON methods. An attacker could possibly use this
issue to inject arbitrary code into the Go template. (CVE-2024-24785)");

  script_tag(name:"affected", value:"'golang-1.17' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17", ver:"1.17.13-3ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17-go", ver:"1.17.13-3ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17-src", ver:"1.17.13-3ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
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
