# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7552.1");
  script_cve_id("CVE-2021-39929", "CVE-2021-4182", "CVE-2021-4185", "CVE-2021-4186", "CVE-2022-0581", "CVE-2022-0582", "CVE-2022-0583", "CVE-2022-0585", "CVE-2022-0586", "CVE-2022-3190");
  script_tag(name:"creation_date", value:"2025-06-06 04:11:22 +0000 (Fri, 06 Jun 2025)");
  script_version("2025-06-06T05:41:39+0000");
  script_tag(name:"last_modification", value:"2025-06-06 05:41:39 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 18:07:47 +0000 (Wed, 23 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-7552-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7552-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7552-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the USN-7552-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Wireshark did not correctly handle recursion. If a
user or system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
and Ubuntu 20.04 LTS. (CVE-2021-39929)

Roman Donchenko discovered that Wireshark did not correctly handle
parsing certain files. If a user or system were tricked into opening a
specially crafted file, an attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
(CVE-2021-4182)

It was discovered that Wireshark did not correctly handle parsing
certain files. If a user or system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS,
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2021-4185, CVE-2022-0581)

It was discovered that Wireshark did not correctly handle parsing
certain files. If a user or system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-4186)

Sharon Brizinov discovered that Wireshark did not correctly handle
parsing certain files. If a user or system were tricked into opening a
specially crafted file, an attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2022-0582, CVE-2022-0583, CVE-2022-0586)

Sharon Brizinov discovered that Wireshark did not correctly handle
parsing certain files. If a user or system were tricked into opening a
specially crafted file, an attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
(CVE-2022-0585)

Jason Cohen discovered that Wireshark did not correctly handle parsing
certain files. If a user or system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 22.04 LTS.
(CVE-2022-3190)");

  script_tag(name:"affected", value:"'wireshark' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.10-1~ubuntu14.04.0~esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.10-1~ubuntu16.04.0+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark11", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"2.6.10-1~ubuntu18.04.0+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark13", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"3.2.3-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libwireshark15", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"tshark", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-common", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-gtk", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wireshark-qt", ver:"3.6.2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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
