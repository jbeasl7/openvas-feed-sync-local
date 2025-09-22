# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7603.1");
  script_cve_id("CVE-2022-24828", "CVE-2023-43655", "CVE-2024-24821", "CVE-2024-35241", "CVE-2024-35242");
  script_tag(name:"creation_date", value:"2025-06-30 10:21:48 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-07-01T05:42:02+0000");
  script_tag(name:"last_modification", value:"2025-07-01 05:42:02 +0000 (Tue, 01 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-04 01:46:28 +0000 (Wed, 04 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-7603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7603-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7603-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'composer' package(s) announced via the USN-7603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Thomas Chauchefoin discovered that Composer did not correctly handle
certain arguments. An attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-24828, CVE-2023-43655)

Ed Cradock discovered that Composer did not correctly handle the exclusion
of certain files. An attacker could possibly use this issue to execute
arbitrary code. This issue only affected Ubuntu 22.04 LTS. (CVE-2024-24821)

Martin Haunschmid discovered that Composer did not correctly handle git
branch names. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2024-35241)

Maciej Piechota discovered that Composer did not correctly handle VCS
branch names. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2024-35242)");

  script_tag(name:"affected", value:"'composer' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"composer", ver:"1.0.0~beta2-1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"composer", ver:"1.6.3-1ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"composer", ver:"1.10.1-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"composer", ver:"2.2.6-2ubuntu4+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"composer", ver:"2.7.1-2ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
