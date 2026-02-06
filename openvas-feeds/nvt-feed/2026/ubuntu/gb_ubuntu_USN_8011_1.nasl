# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8011.1");
  script_cve_id("CVE-2024-53920", "CVE-2025-1244");
  script_tag(name:"creation_date", value:"2026-02-05 04:34:59 +0000 (Thu, 05 Feb 2026)");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-12 15:15:18 +0000 (Wed, 12 Feb 2025)");

  script_name("Ubuntu: Security Advisory (USN-8011-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8011-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8011-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs' package(s) announced via the USN-8011-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Emacs could trigger unsafe Lisp macro expansion,
when a user invoked elisp-completion-at-point on untrusted Emacs Lisp
source code. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2024-53920)

It was discovered that Emacs did not properly sanitize input when
handling certain URI schemes. An attacker could possibly use this issue
to execute arbitrary shell commands by tricking a user into opening a
specially crafted URL. (CVE-2025-1244)");

  script_tag(name:"affected", value:"'emacs' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-gtk", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-lucid", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-nox", ver:"1:26.3+1-1ubuntu2+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-gtk", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-lucid", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-nox", ver:"1:27.1+1-3ubuntu5.2+esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"emacs", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-bin-common", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-common", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-el", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-gtk", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-lucid", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-nox", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"emacs-pgtk", ver:"1:29.3+1-1ubuntu2+esm3", rls:"UBUNTU24.04 LTS"))) {
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
