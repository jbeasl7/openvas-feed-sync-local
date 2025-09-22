# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6886.1");
  script_cve_id("CVE-2023-45288", "CVE-2023-45289", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24785", "CVE-2024-24788", "CVE-2024-24789", "CVE-2024-24790");
  script_tag(name:"creation_date", value:"2024-07-10 04:09:27 +0000 (Wed, 10 Jul 2024)");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:59:12 +0000 (Tue, 18 Jun 2024)");

  script_name("Ubuntu: Security Advisory (USN-6886-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6886-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6886-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-1.21, golang-1.22' package(s) announced via the USN-6886-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Go net/http module did not properly handle the
requests when request\'s headers exceed MaxHeaderBytes. An attacker could
possibly use this issue to cause a panic resulting into a denial of service.
This issue only affected Go 1.21 in Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2023-45288)

It was discovered that the Go net/http module did not properly validate the
subdomain match or exact match of the initial domain. An attacker could
possibly use this issue to read sensitive information. This issue only
affected Go 1.21 in Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-45289)

It was discovered that the Go net/http module did not properly validate the
total size of the parsed form when parsing a multipart form. An attacker
could possibly use this issue to cause a panic resulting into a denial of
service. This issue only affected Go 1.21 in Ubuntu 20.04 LTS and Ubuntu
22.04 LTS. (CVE-2023-45290)

It was discovered that the Go crypto/x509 module did not properly handle a
certificate chain which contains a certificate with an unknown public key
algorithm. An attacker could possibly use this issue to cause a panic
resulting into a denial of service. This issue only affected Go 1.21 in
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-24783)

It was discovered that the Go net/mail module did not properly handle
comments within display names in the ParseAddressList function. An
attacker could possibly use this issue to cause a panic resulting into a
denial of service. This issue only affected Go 1.21 in Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2024-24784)

It was discovered that the Go html/template module did not validate errors
returned from MarshalJSON methods. An attacker could possibly use this
issue to inject arbitrary code into the Go template. This issue only
affected Go 1.21 in Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-24785)

It was discovered that the Go net module did not properly validate the DNS
message in response to a query. An attacker could possibly use this issue
to cause a panic resulting into a denial of service. This issue only
affected Go 1.22. (CVE-2024-24788)

It was discovered that the Go archive/zip module did not properly handle
certain types of invalid zip files differs from the behavior of most zip
implementations. An attacker could possibly use this issue to cause a panic
resulting into a denial of service. (CVE-2024-24789)

It was discovered that the Go net/netip module did not work as expected
for IPv4-mapped IPv6 addresses in various Is methods. An attacker could
possibly use this issue to cause a panic resulting into a denial of service.
(CVE-2024-24790)");

  script_tag(name:"affected", value:"'golang-1.21, golang-1.22' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1~ubuntu20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1~ubuntu20.04.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1~ubuntu20.04.3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.1-1~ubuntu22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.1-1~ubuntu22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.1-1~ubuntu22.04.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22", ver:"1.22.2-2~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22-go", ver:"1.22.2-2~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22-src", ver:"1.22.2-2~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21", ver:"1.21.9-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-go", ver:"1.21.9-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.21-src", ver:"1.21.9-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22", ver:"1.22.2-2ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22-go", ver:"1.22.2-2ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"golang-1.22-src", ver:"1.22.2-2ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
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
