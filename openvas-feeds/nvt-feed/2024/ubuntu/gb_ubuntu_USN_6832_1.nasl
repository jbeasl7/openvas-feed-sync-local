# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6832.1");
  script_cve_id("CVE-2023-31607", "CVE-2023-31608", "CVE-2023-31609", "CVE-2023-31610", "CVE-2023-31611", "CVE-2023-31612", "CVE-2023-31613", "CVE-2023-31614", "CVE-2023-31615", "CVE-2023-31616", "CVE-2023-31617", "CVE-2023-31618", "CVE-2023-31619", "CVE-2023-31623", "CVE-2023-31625", "CVE-2023-31628");
  script_tag(name:"creation_date", value:"2024-06-14 04:07:51 +0000 (Fri, 14 Jun 2024)");
  script_version("2024-06-14T05:05:48+0000");
  script_tag(name:"last_modification", value:"2024-06-14 05:05:48 +0000 (Fri, 14 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 13:30:01 +0000 (Mon, 22 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6832-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6832-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6832-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtuoso-opensource' package(s) announced via the USN-6832-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jingzhou Fu discovered that Virtuoso Open-Source Edition incorrectly
handled certain crafted SQL statements. An attacker could possibly use
this issue to crash the program, resulting in a denial of service.
(CVE-2023-31607, CVE-2023-31608, CVE-2023-31609, CVE-2023-31610,
CVE-2023-31611, CVE-2023-31616, CVE-2023-31617, CVE-2023-31618,
CVE-2023-31619, CVE-2023-31623, CVE-2023-31625, CVE-2023-31628)

Jingzhou Fu discovered that Virtuoso Open-Source Edition incorrectly
handled certain crafted SQL statements. An attacker could possibly use
this issue to crash the program, resulting in a denial of service.
This issue only affects Ubuntu 22.04 LTS, Ubuntu 23.10 and Ubuntu
24.04 LTS. (CVE-2023-31612, CVE-2023-31613, CVE-2023-31614,
CVE-2023-31615)");

  script_tag(name:"affected", value:"'virtuoso-opensource' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"6.1.6+repack-0ubuntu5+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1", ver:"6.1.6+repack-0ubuntu5+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1-bin", ver:"6.1.6+repack-0ubuntu5+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"6.1.6+repack-0ubuntu9+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1", ver:"6.1.6+repack-0ubuntu9+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1-bin", ver:"6.1.6+repack-0ubuntu9+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"6.1.6+repack-0ubuntu10+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1", ver:"6.1.6+repack-0ubuntu10+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-6.1-bin", ver:"6.1.6+repack-0ubuntu10+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"7.2.5.1+dfsg1-0.2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7", ver:"7.2.5.1+dfsg1-0.2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7-bin", ver:"7.2.5.1+dfsg1-0.2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"7.2.5.1+dfsg1-0.3ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7", ver:"7.2.5.1+dfsg1-0.3ubuntu1.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7-bin", ver:"7.2.5.1+dfsg1-0.3ubuntu1.1", rls:"UBUNTU23.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource", ver:"7.2.5.1+dfsg1-0.8ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7", ver:"7.2.5.1+dfsg1-0.8ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtuoso-opensource-7-bin", ver:"7.2.5.1+dfsg1-0.8ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
