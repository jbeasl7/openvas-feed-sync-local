# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7488.1");
  script_cve_id("CVE-2024-11168", "CVE-2024-6232", "CVE-2024-9287");
  script_tag(name:"creation_date", value:"2025-05-07 09:14:49 +0000 (Wed, 07 May 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 18:47:16 +0000 (Mon, 10 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-7488-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7488-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7488-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4, python3.6, python3.7, python3.8, python3.9, python3.11, python3.13' package(s) announced via the USN-7488-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Python incorrectly handled parsing bracketed hosts.
A remote attacker could possibly use this issue to perform a Server-Side
Request Forgery (SSRF) attack. This issue only affected python 2.7 and
python3.4 on Ubuntu 14.04 LTS, python2.7 on Ubuntu 16.04 LTS,
python2.7, python3.6, python3.7, and python3.8 on Ubuntu 18.04 LTS,
python2.7 and python3.9 on Ubuntu 20.04 LTS, and python2.7 and
python3.11 on Ubuntu 22.04 LTS. (CVE-2024-11168)

It was discovered that Python allowed excessive backtracking while
parsing certain tarfile headers. A remote attacker could possibly use
this issue to cause Python to consume excessive resources, leading to
a denial of service. This issue only affected python3.4 on
Ubuntu 14.04 LTS, python3.6, python3.7, and python3.8 on
Ubuntu 18.04 LTS, python3.9 on Ubuntu 20.04 LTS, and python3.11 on
Ubuntu 22.04 LTS. (CVE-2024-6232)

It was discovered that Python incorrectly handled quoted path names
when using the venv module. A local attacker able to control virtual
environments could possibly use this issue to execute arbitrary code
when the virtual environment is activated. This issue only affected
python3.4 on Ubuntu 14.04 LTS, python3.6, python3.7, and python3.8
on Ubuntu 18.04 LTS, python3.9 on Ubuntu 20.04 LTS, python3.11 on
Ubuntu 22.04 LTS, and python3.13 on Ubuntu 24.10. (CVE-2024-9287)");

  script_tag(name:"affected", value:"'python2.7, python3.4, python3.6, python3.7, python3.8, python3.9, python3.11, python3.13' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm24", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.6-8ubuntu0.6+esm24", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4", ver:"3.4.3-1ubuntu1~14.04.7+esm14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-minimal", ver:"3.4.3-1ubuntu1~14.04.7+esm14", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-venv", ver:"3.4.3-1ubuntu1~14.04.7+esm14", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.12-1ubuntu0~16.04.18+esm15", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.12-1ubuntu0~16.04.18+esm15", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.17-1~18.04ubuntu1.13+esm10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.17-1~18.04ubuntu1.13+esm10", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6", ver:"3.6.9-1~18.04ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6-minimal", ver:"3.6.9-1~18.04ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.6-venv", ver:"3.6.9-1~18.04ubuntu1.13+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.5-2ubuntu1~18.04.2+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.5-2ubuntu1~18.04.2+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-venv", ver:"3.7.5-2ubuntu1~18.04.2+esm4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.0-3ubuntu1~18.04.2+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.0-3ubuntu1~18.04.2+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-venv", ver:"3.8.0-3ubuntu1~18.04.2+esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-1~20.04.7+esm6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.18-1~20.04.7+esm6", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9", ver:"3.9.5-3ubuntu0~20.04.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-minimal", ver:"3.9.5-3ubuntu0~20.04.1+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.9-venv", ver:"3.9.5-3ubuntu0~20.04.1+esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-13ubuntu1.5+esm5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.18-13ubuntu1.5+esm5", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11", ver:"3.11.0~rc1-1~22.04.1~esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11-minimal", ver:"3.11.0~rc1-1~22.04.1~esm2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.11-venv", ver:"3.11.0~rc1-1~22.04.1~esm2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3.13", ver:"3.13.0-1ubuntu0.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.13-minimal", ver:"3.13.0-1ubuntu0.1", rls:"UBUNTU24.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.13-venv", ver:"3.13.0-1ubuntu0.1", rls:"UBUNTU24.10"))) {
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
