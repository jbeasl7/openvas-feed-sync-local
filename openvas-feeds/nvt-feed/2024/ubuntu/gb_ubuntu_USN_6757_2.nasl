# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6757.2");
  script_cve_id("CVE-2022-4900", "CVE-2024-2756", "CVE-2024-3096");
  script_tag(name:"creation_date", value:"2024-05-03 04:10:49 +0000 (Fri, 03 May 2024)");
  script_version("2024-05-03T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-05-03 05:05:25 +0000 (Fri, 03 May 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 17:46:13 +0000 (Thu, 09 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6757-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6757-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6757-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.4, php8.1, php8.2' package(s) announced via the USN-6757-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6757-1 fixed vulnerabilities in PHP. Unfortunately these fixes were incomplete for
Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.10. This update fixes the problem.

Original advisory details:

 It was discovered that PHP incorrectly handled PHP_CLI_SERVER_WORKERS variable.
 An attacker could possibly use this issue to cause a crash or execute
 arbitrary code. This issue only affected Ubuntu 20.04 LTS, and
 Ubuntu 22.04 LTS. (CVE-2022-4900)

 It was discovered that PHP incorrectly handled certain cookies.
 An attacker could possibly use this issue to cookie by pass.
 (CVE-2024-2756)

 It was discovered that PHP incorrectly handled some passwords.
 An attacker could possibly use this issue to cause an account takeover
 attack. (CVE-2024-3096)");

  script_tag(name:"affected", value:"'php7.4, php8.1, php8.2' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.4", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cgi", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cli", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-fpm", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-xml", ver:"7.4.3-4ubuntu2.22", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php8.1", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cgi", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-cli", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-fpm", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.1-xml", ver:"8.1.2-1ubuntu2.17", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php8.2", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.2", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.2-cgi", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.2-cli", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.2-fpm", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.2-xml", ver:"8.2.10-2ubuntu2.1", rls:"UBUNTU23.10"))) {
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
