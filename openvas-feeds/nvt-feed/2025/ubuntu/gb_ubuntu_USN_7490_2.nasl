# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7490.2");
  script_cve_id("CVE-2025-32912");
  script_tag(name:"creation_date", value:"2025-05-07 09:14:49 +0000 (Wed, 07 May 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-14 15:15:25 +0000 (Mon, 14 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7490-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7490-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7490-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2110056");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup2.4' package(s) announced via the USN-7490-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7490-1 fixed vulnerabilities in libsoup. It was discovered that the fix
for CVE-2025-32912 was incomplete. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Tan Wei Chong discovered that libsoup incorrectly handled memory when
 parsing HTTP request headers. An attacker could possibly use this issue to
 send a maliciously crafted HTTP request to the server, causing a denial of
 service. (CVE-2025-32906)

 Alon Zahavi discovered that libsoup incorrectly parsed video files. An
 attacker could possibly use this issue to send a maliciously crafted HTTP
 response back to the client, causing a denial of service, or leading to
 undefined behavior. (CVE-2025-32909)

 Jan Rozanski discovered that libsoup incorrectly handled memory when
 parsing authentication headers. An attacker could possibly use this issue
 to send a maliciously crafted HTTP response back to the client, causing a
 denial of service. (CVE-2025-32910, CVE-2025-32912)

 It was discovered that libsoup incorrectly handled data in the hash table
 data type. An attacker could possibly use this issue to send a maliciously
 crafted HTTP request to the server, causing a denial of service or remote
 code execution. (CVE-2025-32911)

 Jan Rozanski discovered that libsoup incorrectly handled memory when
 parsing the content disposition HTTP header. An attacker could possibly
 use this issue to send maliciously crafted data to a client or server,
 causing a denial of service. (CVE-2025-32913)

 Alon Zahavi discovered that libsoup incorrectly handled memory when
 parsing HTTP requests. An attacker could possibly use this issue to send a
 maliciously crafted HTTP request to the server, causing a denial of
 service or obtaining sensitive information. (CVE-2025-32914)

 It was discovered that libsoup incorrectly handled memory when parsing
 quality-list headers. An attacker could possibly use this issue to send a
 maliciously crafted HTTP request to the server, causing a denial of
 service. (CVE-2025-46420)

 Jan Rozanski discovered that libsoup did not strip authorization
 information upon redirects. An attacker could possibly use this issue to
 obtain sensitive information. (CVE-2025-46421)");

  script_tag(name:"affected", value:"'libsoup2.4' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.52.2-1ubuntu0.3+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.62.1-1ubuntu0.4+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.70.0-1ubuntu0.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup2.4-1", ver:"2.74.2-3ubuntu0.4", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-2.4-1", ver:"2.74.3-6ubuntu1.4", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-2.4-1", ver:"2.74.3-7ubuntu0.4", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-2.4-1", ver:"2.74.3-10ubuntu0.2", rls:"UBUNTU25.04"))) {
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
