# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7027.1");
  script_cve_id("CVE-2022-45939", "CVE-2022-48337", "CVE-2022-48338", "CVE-2022-48339", "CVE-2023-28617", "CVE-2024-30203", "CVE-2024-30204", "CVE-2024-30205", "CVE-2024-39331");
  script_tag(name:"creation_date", value:"2024-09-20 04:08:05 +0000 (Fri, 20 Sep 2024)");
  script_version("2024-09-20T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-09-20 05:05:37 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 16:08:45 +0000 (Thu, 02 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-7027-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7027-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7027-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2070418");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs, emacs24, emacs25' package(s) announced via the USN-7027-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Emacs incorrectly handled input sanitization. An
attacker could possibly use this issue to execute arbitrary commands. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04
LTS. (CVE-2022-45939)

Xi Lu discovered that Emacs incorrectly handled input sanitization. An
attacker could possibly use this issue to execute arbitrary commands. This
issue only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS
and Ubuntu 22.04 LTS. (CVE-2022-48337)

Xi Lu discovered that Emacs incorrectly handled input sanitization. An
attacker could possibly use this issue to execute arbitrary commands. This
issue only affected Ubuntu 22.04 LTS. (CVE-2022-48338)

Xi Lu discovered that Emacs incorrectly handled input sanitization. An
attacker could possibly use this issue to execute arbitrary commands. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04
LTS. (CVE-2022-48339)

It was discovered that Emacs incorrectly handled filename sanitization. An
attacker could possibly use this issue to execute arbitrary commands. This
issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04
LTS. (CVE-2023-28617)

It was discovered that Emacs incorrectly handled certain crafted files. An
attacker could possibly use this issue to crash the program, resulting in
a denial of service. This issue only affected Ubuntu 16.04 LTS, Ubuntu
18.04 LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2024-30203,
CVE-2024-30204, CVE-2024-30205)

It was discovered that Emacs incorrectly handled certain crafted files. An
attacker could possibly use this issue to execute arbitrary commands.
(CVE-2024-39331)");

  script_tag(name:"affected", value:"'emacs, emacs24, emacs25' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"emacs24", ver:"24.5+1-6ubuntu1.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24-bin-common", ver:"24.5+1-6ubuntu1.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24-common", ver:"24.5+1-6ubuntu1.1+esm4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs24-el", ver:"24.5+1-6ubuntu1.1+esm4", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs25", ver:"25.2+1-6ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25-bin-common", ver:"25.2+1-6ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25-common", ver:"25.2+1-6ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs25-el", ver:"25.2+1-6ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:26.3+1-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:26.3+1-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:26.3+1-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:26.3+1-1ubuntu2+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:27.1+1-3ubuntu5.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:27.1+1-3ubuntu5.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:27.1+1-3ubuntu5.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:27.1+1-3ubuntu5.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:29.3+1-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:29.3+1-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:29.3+1-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:29.3+1-1ubuntu2+esm1", rls:"UBUNTU24.04 LTS"))) {
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
