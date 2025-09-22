# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7490.3");
  script_cve_id("CVE-2025-32906", "CVE-2025-32909", "CVE-2025-32910", "CVE-2025-32911", "CVE-2025-32912", "CVE-2025-32913", "CVE-2025-32914", "CVE-2025-46420", "CVE-2025-46421");
  script_tag(name:"creation_date", value:"2025-05-08 04:05:12 +0000 (Thu, 08 May 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7490-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7490-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7490-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup3' package(s) announced via the USN-7490-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7490-1 fixed vulnerabilities in libsoup2.4. This update provides the
corresponding updates for libsoup3.

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

  script_tag(name:"affected", value:"'libsoup3' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.0.7-0ubuntu1+esm3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.4.4-5ubuntu0.3", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libsoup-3.0-0", ver:"3.6.0-2ubuntu0.3", rls:"UBUNTU24.10"))) {
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
