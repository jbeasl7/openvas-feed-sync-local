# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7010.2");
  script_cve_id("CVE-2021-41687");
  script_tag(name:"creation_date", value:"2025-07-10 08:14:31 +0000 (Thu, 10 Jul 2025)");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-06 19:44:43 +0000 (Wed, 06 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-7010-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7010-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7010-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the USN-7010-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7010-1 fixed vulnerabilities in DCMTK. The update introduced a
regression. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Jinsheng Ba discovered that DCMTK incorrectly handled certain requests. If
 a user or an automated system were tricked into opening a certain specially
 crafted input file, a remote attacker could possibly use this issue to
 cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
 (CVE-2021-41687, CVE-2021-41688, CVE-2021-41689, CVE-2021-41690)

 Sharon Brizinov and Noam Moshe discovered that DCMTK incorrectly handled
 pointers. If a user or an automated system were tricked into opening a
 certain specially crafted input file, a remote attacker could possibly use
 this issue to cause a denial of service. This issue only affected
 Ubuntu 20.04 LTS. (CVE-2022-2121)

 It was discovered that DCMTK incorrectly handled certain inputs. If a
 user or an automated system were tricked into opening a certain specially
 crafted input file, a remote attacker could possibly use this issue to
 cause a denial of service. This issue only affected Ubuntu 20.04 LTS.
 (CVE-2022-43272)

 It was discovered that DCMTK incorrectly handled certain inputs. If a
 user or an automated system were tricked into opening a certain specially
 crafted input file, a remote attacker could possibly use this issue to
 execute arbitrary code. This issue was only addressed in Ubuntu 20.04 LTS
 and Ubuntu 22.04 LTS. (CVE-2024-28130)

 It was discovered that DCMTK incorrectly handled memory when processing an
 invalid incoming DIMSE message. An attacker could possibly use this issue
 to cause a denial of service. (CVE-2024-34508, CVE-2024-34509)");

  script_tag(name:"affected", value:"'dcmtk' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dcmtk", ver:"3.6.1~20150924-5ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdcmtk5", ver:"3.6.1~20150924-5ubuntu0.1~esm3", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dcmtk", ver:"3.6.2-3ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdcmtk12", ver:"3.6.2-3ubuntu0.1~esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"dcmtk", ver:"3.6.4-2.1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libdcmtk14", ver:"3.6.4-2.1ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
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
