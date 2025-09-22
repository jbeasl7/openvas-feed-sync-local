# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7203.1");
  script_cve_id("CVE-2018-1046", "CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644", "CVE-2020-17482", "CVE-2022-27227");
  script_tag(name:"creation_date", value:"2025-01-15 23:12:28 +0000 (Wed, 15 Jan 2025)");
  script_version("2025-01-16T05:37:14+0000");
  script_tag(name:"last_modification", value:"2025-01-16 05:37:14 +0000 (Thu, 16 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-17 16:47:19 +0000 (Mon, 17 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-7203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7203-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7203-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns, pdns-recursor' package(s) announced via the USN-7203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Wei Hao discovered that PowerDNS Authoritative Server incorrectly handled
memory when accessing certain files. An attacker could possibly use this
issue to achieve arbitrary code execution. (CVE-2018-1046)

It was discovered that PowerDNS Authoritative Server and PowerDNS Recursor
incorrectly handled memory when receiving certain remote input. An attacker
could possibly use this issue to cause denial of service. (CVE-2018-10851)

Kees Monshouwer discovered that PowerDNS Authoritative Server and PowerDNS
Recursor incorrectly handled request validation after having cached
malformed input. An attacker could possibly use this issue to cause denial
of service. (CVE-2018-14626)

Toshifumi Sakaguchi discovered that PowerDNS Recursor incorrectly handled
requests after having cached malformed input. An attacker could possibly
use this issue to cause denial of service. (CVE-2018-14644)

Nathaniel Ferguson discovered that PowerDNS Authoritative Server
incorrectly handled memory when receiving certain remote input. An attacker
could possibly use this issue to obtain sensitive information.
(CVE-2020-17482)

Nicolas Dehaine and Dmitry Shabanov discovered that PowerDNS Authoritative
Server and PowerDNS Recursor incorrectly handled IXFR requests in certain
circumstances. An attacker could possibly use this issue to cause denial of
service. (CVE-2022-27227)");

  script_tag(name:"affected", value:"'pdns, pdns-recursor' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"4.0.0~alpha2-2ubuntu0.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"4.0.0~alpha2-3ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-tools", ver:"4.0.0~alpha2-3ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"4.1.1-2ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"4.1.1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-tools", ver:"4.1.1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"4.2.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"4.2.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-tools", ver:"4.2.1-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"pdns-recursor", ver:"4.6.0-1ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"4.5.3-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pdns-tools", ver:"4.5.3-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
