# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7587.1");
  script_cve_id("CVE-2020-21680", "CVE-2020-21682", "CVE-2020-21683", "CVE-2025-31162", "CVE-2025-31163", "CVE-2025-31164");
  script_tag(name:"creation_date", value:"2025-06-24 04:10:04 +0000 (Tue, 24 Jun 2025)");
  script_version("2025-06-24T05:41:22+0000");
  script_tag(name:"last_modification", value:"2025-06-24 05:41:22 +0000 (Tue, 24 Jun 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-16 12:54:16 +0000 (Mon, 16 Aug 2021)");

  script_name("Ubuntu: Security Advisory (USN-7587-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7587-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7587-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fig2dev' package(s) announced via the USN-7587-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Suhwan Song discovered that Fig2dev did not correctly handle certain
memory operations. If a user or automated system were tricked into
opening a specially crafted file, an attacker could possibly use this
issue to cause a denial of service. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 20.04 LTS. (CVE-2020-21680, CVE-2020-21682,
CVE-2020-21683)

It was discovered that Fig2dev did not limit the size of certain inputs.
If a user or automated system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a
denial of service. (CVE-2025-31162, CVE-2025-31163)

It was discovered that Fig2dev did not correctly handle certain inputs.
If a user or automated system were tricked into opening a specially
crafted file, an attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 24.04 LTS and
Ubuntu 24.10. (CVE-2025-31164)");

  script_tag(name:"affected", value:"'fig2dev' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.6a-6ubuntu1.1+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"transfig", ver:"1:3.2.6a-6ubuntu1.1+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.7a-7ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.8b-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.9-3ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"fig2dev", ver:"1:3.2.9-4ubuntu0.1", rls:"UBUNTU24.10"))) {
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
