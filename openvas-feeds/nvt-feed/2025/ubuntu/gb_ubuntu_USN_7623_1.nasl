# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7623.1");
  script_cve_id("CVE-2023-39327", "CVE-2024-29508", "CVE-2024-56826", "CVE-2024-56827", "CVE-2025-27832", "CVE-2025-27835", "CVE-2025-27836", "CVE-2025-48708");
  script_tag(name:"creation_date", value:"2025-07-10 08:14:31 +0000 (Thu, 10 Jul 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-09 04:15:12 +0000 (Thu, 09 Jan 2025)");

  script_name("Ubuntu: Security Advisory (USN-7623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7623-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7623-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-7623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJPEG, vendored in Ghostscript did not correctly
handle large image files. If a user or system were tricked into opening a
specially crafted file, an attacker could possibly use this issue to cause
a denial of service. This issue only affected Ubuntu 16.04 LTS and Ubuntu
18.04 LTS. (CVE-2023-39327) Thomas Rinsma discovered that Ghostscript did
not correctly handle printing certain variables. An attacker could possibly
use this issue to leak sensitive information. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-29508) It was discovered
that Ghostscript did not correctly handle loading certain libraries. An
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 16.04 LTS. (CVE-2024-33871) It was discovered
that Ghostscript did not correctly handle certain memory operations. An
attacker could possibly use this issue to execute arbitrary code. This
issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-56826,
CVE-2024-56827, CVE-2025-27832, CVE-2025-27835, CVE-2025-27836) Vasileios
Flengas discovered that Ghostscript did not correctly handle argument
sanitization. An attacker could possibly use this issue to leak sensitive
information. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS, Ubuntu 24.10 and Ubuntu 25.04. (CVE-2025-48708)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.26~dfsg+0-0ubuntu0.16.04.14+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.26~dfsg+0-0ubuntu0.16.04.14+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"9.26~dfsg+0-0ubuntu0.16.04.14+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.26~dfsg+0-0ubuntu0.16.04.14+esm9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.26~dfsg+0-0ubuntu0.16.04.14+esm9", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.26~dfsg+0-0ubuntu0.18.04.18+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.26~dfsg+0-0ubuntu0.18.04.18+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs-dev", ver:"9.26~dfsg+0-0ubuntu0.18.04.18+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.26~dfsg+0-0ubuntu0.18.04.18+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.26~dfsg+0-0ubuntu0.18.04.18+esm4", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.50~dfsg-5ubuntu4.15+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.55.0~dfsg1-0ubuntu5.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.55.0~dfsg1-0ubuntu5.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.55.0~dfsg1-0ubuntu5.12", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.02.1~dfsg1-0ubuntu7.7", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.02.1~dfsg1-0ubuntu7.7", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.03.1~dfsg1-0ubuntu2.4", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.03.1~dfsg1-0ubuntu2.4", rls:"UBUNTU24.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"10.05.0dfsg1-0ubuntu1.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs10", ver:"10.05.0dfsg1-0ubuntu1.1", rls:"UBUNTU25.04"))) {
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
