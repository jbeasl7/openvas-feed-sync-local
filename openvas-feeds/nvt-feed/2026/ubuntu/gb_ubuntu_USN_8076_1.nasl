# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8076.1");
  script_cve_id("CVE-2020-13962", "CVE-2020-17507", "CVE-2022-25255", "CVE-2023-51714", "CVE-2024-39936");
  script_tag(name:"creation_date", value:"2026-03-09 04:37:02 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 16:36:01 +0000 (Thu, 04 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-8076-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8076-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8076-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase-opensource-src' package(s) announced via the USN-8076-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Qt did not correctly handle OpenSSL's error queue.
An attacker could possibly use this issue to cause a denial of service.
This issue was only addressed in Ubuntu 20.04 LTS. (CVE-2020-13962)

It was discovered that Qt incorrectly handled certain XBM image files. If a
user or automated system were tricked into opening a specially crafted PPM
file, a remote attacker could cause Qt to crash, resulting in a denial of
service. This issue was only addressed in Ubuntu 16.04 LTS and
Ubuntu 20.04 LTS. (CVE-2020-17507)

It was discovered that Qt did not correctly handle executing specific
binaries. If a user or automated system were tricked into executing a
binary at a specific file path, an attacker could cause a denial of
service or execute arbitrary code. This issue was only addressed in
Ubuntu 20.04 LTS. (CVE-2022-25255)

It was discovered that Qt did not correctly handle certain integer
arithmetic. An attacker could possibly use this issue to cause a denial
of service. This issue was only addressed in Ubuntu 18.04 LTS,
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-51714)

It was discovered that Qt did not correctly handle certain encrypted
connections. An attacker could possibly use this issue to leak sensitive
information. This issue was only addressed in Ubuntu 24.04 LTS.
(CVE-2024-39936)");

  script_tag(name:"affected", value:"'qtbase-opensource-src' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.5.1+dfsg-16ubuntu7.7+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.5.1+dfsg-16ubuntu7.7+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.9.5+dfsg-0ubuntu2.6+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.9.5+dfsg-0ubuntu2.6+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.12.8+dfsg-0ubuntu2.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.12.8+dfsg-0ubuntu2.1+esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5a", ver:"5.15.3+dfsg-2ubuntu0.2+esm3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5", ver:"5.15.3+dfsg-2ubuntu0.2+esm3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libqt5core5t64", ver:"5.15.13+dfsg-1ubuntu1+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libqt5gui5t64", ver:"5.15.13+dfsg-1ubuntu1+esm1", rls:"UBUNTU24.04 LTS"))) {
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
