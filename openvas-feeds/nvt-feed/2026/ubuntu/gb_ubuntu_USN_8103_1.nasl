# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8103.1");
  script_cve_id("CVE-2020-18771", "CVE-2020-18899", "CVE-2025-54080", "CVE-2025-55304", "CVE-2026-25884", "CVE-2026-27596", "CVE-2026-27631");
  script_tag(name:"creation_date", value:"2026-03-19 04:39:53 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-19T05:56:32+0000");
  script_tag(name:"last_modification", value:"2026-03-19 05:56:32 +0000 (Thu, 19 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-05 12:32:39 +0000 (Thu, 05 Mar 2026)");

  script_name("Ubuntu: Security Advisory (USN-8103-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-8103-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8103-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exiv2' package(s) announced via the USN-8103-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Exiv2 did not correctly handle reading certain
buffers. An attacker could possibly use this issue to leak sensitive
information. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04
LTS. (CVE-2020-18771)

Wen Cheng discovered that Exiv2 did not correctly handle certain memory
allocation. If a user or system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.
(CVE-2020-18899)

It was discovered that Exiv2 did not correctly handle writing certain
metadata. If a user or system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service. (CVE-2025-54080)

It was discovered that Exiv2 did not correctly handle parsing certain
metadata. If a user or system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS,
Ubuntu 24.04 LTS and Ubuntu 25.10. (CVE-2025-55304)

It was discovered that Exiv2 did not correctly handle parsing certain
images. If a user or system were tricked into opening a specially crafted
file, an attacker could possibly use this issue to cause a denial of
service. (CVE-2026-25884)

It was discovered that Exiv2 did not correctly handle previewing certain
images. An attacker could possibly use this issue to cause a denial of
service. (CVE-2026-27596)

It was discovered that Exiv2 did not correctly handle certain integer
arithmetic. An attacker could possibly use this issue to cause a denial of
service. (CVE-2026-27631)");

  script_tag(name:"affected", value:"'exiv2' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-2.1ubuntu16.04.7+esm5", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.25-3.1ubuntu0.18.04.11+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.27.2-8ubuntu2.7+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.27.5-3ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.27.6-1ubuntu0.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"exiv2", ver:"0.28.5+dfsg-1ubuntu0.1", rls:"UBUNTU25.10"))) {
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
