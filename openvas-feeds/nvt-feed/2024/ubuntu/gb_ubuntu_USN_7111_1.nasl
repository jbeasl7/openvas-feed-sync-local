# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7111.1");
  script_cve_id("CVE-2022-41723", "CVE-2022-41724", "CVE-2022-41725", "CVE-2023-24536", "CVE-2023-39323", "CVE-2023-45288", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24789", "CVE-2024-24791", "CVE-2024-34155", "CVE-2024-34156", "CVE-2024-34158");
  script_tag(name:"creation_date", value:"2024-11-15 04:08:07 +0000 (Fri, 15 Nov 2024)");
  script_version("2024-11-15T15:55:05+0000");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 18:04:15 +0000 (Thu, 04 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-7111-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7111-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7111-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.17' package(s) announced via the USN-7111-1 advisory.");

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

Jakob Ackermann discovered that Go incorrectly handled multipart
forms. An attacker could possibly use this issue to consume an excessive
amount of resources, resulting in a denial of service. (CVE-2023-24536)

It was discovered that Go did not properly validate the '//go:cgo_'
directives during compilation. An attacker could possibly use this issue
to inject arbitrary code during compile time. (CVE-2023-39323)

Bartek Nowotarski was discovered that the Go net/http module did not
properly handle the requests when request's headers exceed MaxHeaderBytes.
An attacker could possibly use this issue to cause a panic resulting into
a denial of service. (CVE-2023-45288)

Bartek Nowotarski discovered that the Go net/http module did not properly
validate the total size of the parsed form when parsing a multipart form.
An attacker could possibly use this issue to cause a panic resulting into a
denial of service. (CVE-2023-45290)

John Howard discovered that the Go crypto/x509 module did not properly
handle a certificate chain which contains a certificate with an unknown
public key algorithm. An attacker could possibly use this issue to cause
a panic resulting into a denial of service. (CVE-2024-24783)

Juho Nurminen discovered that the Go net/mail module did not properly
handle comments within display names in the ParseAddressList function.
An attacker could possibly use this issue to cause a panic resulting into
a denial of service. (CVE-2024-24784)

Yufan You discovered that the Go archive/zip module did not properly
handle certain types of invalid zip files differs from the behavior of
most zip implementations. An attacker could possibly use this issue to
cause a panic resulting into a denial of service. (CVE-2024-24789)

Geoff Franks discovered that the Go net/http module did not properly
handle responses to requests with an 'Expect: 100-continue' header under
certain circumstances. An attacker could possibly use this issue to
cause a denial of service. (CVE-2024-24791)

It was discovered that the Go parser module did not properly handle deeply
nested literal values. An attacker could possibly use this issue to cause
a panic resulting in a denial of service. (CVE-2024-34155)

Md Sakib Anwar discovered that the Go encoding/gob module did not properly
handle message ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17", ver:"1.17.13-3ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17-go", ver:"1.17.13-3ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.17-src", ver:"1.17.13-3ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
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
