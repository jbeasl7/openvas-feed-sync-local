# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8018.3");
  script_cve_id("CVE-2025-12084", "CVE-2025-15282", "CVE-2026-0672", "CVE-2026-0865");
  script_tag(name:"creation_date", value:"2026-03-20 04:34:56 +0000 (Fri, 20 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-16 21:13:09 +0000 (Tue, 16 Dec 2025)");

  script_name("Ubuntu: Security Advisory (USN-8018-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8018-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8018-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7' package(s) announced via the USN-8018-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8018-1 fixed CVE-2025-12084, CVE-2025-15282, CVE-2026-0672,
CVE-2026-0865 for python3. This update provides the corresponding updates
for python2.7.

Original advisory details:

 Denis Ledoux discovered that Python incorrectly parsed email message
 headers. An attacker could possibly use this issue to inject arbitrary
 headers into email messages. This issue only affected python3.6,
 python3.7, python3.8, python3.9, python3.10, python3.11, python3.12,
 python3.13, and python3.14 packages. (CVE-2025-11468)

 Jacob Walls, Shai Berger, and Natalia Bidart discovered that Python
 inefficiently parsed XML input with quadratic complexity. An attacker
 could possibly use this issue to cause a denial of service.
 (CVE-2025-12084)

 It was discovered that Python incorrectly parsed malicious plist files. An
 attacker could possibly use this issue to cause Python to use excessive
 resources, leading to a denial of service. This issue only affected
 python3.5, python3.6, python3.7, python3.8, python3.9, python3.10,
 python3.11, python3.12, python3.13, and python3.14 packages.
 (CVE-2025-13837)

 Omar Hasan discovered that Python incorrectly parsed URL mediatypes. An
 attacker could possibly use this issue to inject arbitrary HTTP headers.
 (CVE-2025-15282)

 Omar Hasan discovered that Python incorrectly parsed malicious IMAP
 inputs. An attacker could possibly use this issue to inject arbitrary
 IMAP commands. (CVE-2025-15366)

 Omar Hasan discovered that Python incorrectly parsed malicious POP3
 inputs. An attacker could possibly use this issue to inject arbitrary
 POP3 commands. (CVE-2025-15367)

 Omar Hasan discovered that Python incorrectly parsed malicious HTTP cookie
 headers. An attacker could possibly use this issue to inject arbitrary
 HTTP headers. (CVE-2026-0672)

 Omar Hasan discovered that Python incorrectly parsed malicious HTTP header
 names and values. An attacker could possibly use this issue to inject
 arbitrary HTTP headers. (CVE-2026-0865)");

  script_tag(name:"affected", value:"'python2.7' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.6-8ubuntu0.6+esm29", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm29", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.12-1ubuntu0~16.04.18+esm19", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.12-1ubuntu0~16.04.18+esm19", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.17-1~18.04ubuntu1.13+esm14", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.17-1~18.04ubuntu1.13+esm14", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.18-1~20.04.7+esm9", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-1~20.04.7+esm9", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.18-13ubuntu1.5+esm8", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-13ubuntu1.5+esm8", rls:"UBUNTU22.04 LTS"))) {
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
