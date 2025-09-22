# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7117.2");
  script_cve_id("CVE-2024-10224", "CVE-2024-11003", "CVE-2024-48990", "CVE-2024-48991", "CVE-2024-48992");
  script_tag(name:"creation_date", value:"2024-11-27 04:08:11 +0000 (Wed, 27 Nov 2024)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 17:36:44 +0000 (Tue, 26 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7117-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|24\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7117-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7117-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2089193");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'needrestart' package(s) announced via the USN-7117-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7117-1 fixed vulnerabilities in needrestart. The update introduced a
regression in needrestart. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Qualys discovered that needrestart passed unsanitized data to a library
 (libmodule-scandeps-perl) which expects safe input. A local attacker could
 possibly use this issue to execute arbitrary code as root.
 (CVE-2024-11003)

 Qualys discovered that the library libmodule-scandeps-perl incorrectly
 parsed perl code. This could allow a local attacker to execute arbitrary
 shell commands. (CVE-2024-10224)

 Qualys discovered that needrestart incorrectly used the PYTHONPATH
 environment variable to spawn a new Python interpreter. A local attacker
 could possibly use this issue to execute arbitrary code as root.
 (CVE-2024-48990)

 Qualys discovered that needrestart incorrectly checked the path to the
 Python interpreter. A local attacker could possibly use this issue to win
 a race condition and execute arbitrary code as root. (CVE-2024-48991)

 Qualys discovered that needrestart incorrectly used the RUBYLIB
 environment variable to spawn a new Ruby interpreter. A local attacker
 could possibly use this issue to execute arbitrary code as root.
 (CVE-2024-48992)");

  script_tag(name:"affected", value:"'needrestart' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 24.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"2.6-1ubuntu0.1~esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"3.1-1ubuntu0.1+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"3.4-6ubuntu0.1+esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"3.5-5ubuntu2.3", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"3.6-7ubuntu4.4", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"needrestart", ver:"3.6-8ubuntu4.3", rls:"UBUNTU24.10"))) {
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
