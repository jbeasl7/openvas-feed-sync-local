# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7668.1");
  script_cve_id("CVE-2025-30749", "CVE-2025-30754", "CVE-2025-50059", "CVE-2025-50106");
  script_tag(name:"creation_date", value:"2025-07-28 04:20:22 +0000 (Mon, 28 Jul 2025)");
  script_version("2025-07-28T05:44:47+0000");
  script_tag(name:"last_modification", value:"2025-07-28 05:44:47 +0000 (Mon, 28 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-15 20:15:40 +0000 (Tue, 15 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7668-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7668-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7668-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-21' package(s) announced via the USN-7668-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the 2D component of OpenJDK 21 did not properly
manage memory under certain circumstances. An attacker could possibly
use this issue to cause a denial of service or execute arbitrary code.
(CVE-2025-30749, CVE-2025-50106)

Mashroor Hasan Bhuiyan discovered that the JSSE component of OpenJDK
21 did not properly manage TLS 1.3 handshakes under certain
circumstances. An attacker could possibly use this issue to obtain
sensitive information. (CVE-2025-30754)

Martin van Wingerden and Violeta Georgieva of Broadcom discovered
that the Networking component of OpenJDK 24 did not properly
manage network connections under certain circumstances. An attacker
could possibly use this issue to obtain sensitive information.
(CVE-2025-50059)");

  script_tag(name:"affected", value:"'openjdk-21' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.8+9~us1-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.8+9~us1-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.8+9~us1-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.8+9~us1-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.8+9~us1-0ubuntu1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.8+9~us1-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.8+9~us1-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.8+9~us1-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.8+9~us1-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.8+9~us1-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.8+9~us1-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.8+9~us1-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.8+9~us1-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.8+9~us1-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.8+9~us1-0ubuntu1~24.04.1", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk", ver:"21.0.8+9~us1-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jdk-headless", ver:"21.0.8+9~us1-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre", ver:"21.0.8+9~us1-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-headless", ver:"21.0.8+9~us1-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-21-jre-zero", ver:"21.0.8+9~us1-0ubuntu1~25.04.1", rls:"UBUNTU25.04"))) {
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
