# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.8089.3");
  script_cve_id("CVE-2021-33194", "CVE-2022-27664", "CVE-2022-41723", "CVE-2023-3978", "CVE-2025-22872", "CVE-2025-47911", "CVE-2025-58190");
  script_tag(name:"creation_date", value:"2026-04-08 04:50:57 +0000 (Wed, 08 Apr 2026)");
  script_version("2026-04-08T06:10:32+0000");
  script_tag(name:"last_modification", value:"2026-04-08 06:10:32 +0000 (Wed, 08 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-09 16:36:40 +0000 (Thu, 09 Mar 2023)");

  script_name("Ubuntu: Security Advisory (USN-8089-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-8089-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8089-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'adsys, juju-core, lxd' package(s) announced via the USN-8089-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-8089-1 fixed vulnerabilities in Go Networking. This update provides
the corresponding update to code vendored in LXD, ADSys, and Juju Core.

Original advisory details:

 Bahruz Jabiyev, Tommaso Innocenti, Anthony Gavazzi, Steven Sprecher, and
 Kaan Onarlioglu discovered that servers using Go Networking could hang
 during shutdown if preempted by a fatal error. An attacker could possibly
 use this to cause a denial of service. This issue only affected Ubuntu
 22.04 LTS. (CVE-2022-27664)

 Arpad Ryszka and Jakob Ackermann discovered that a maliciously crafted
 stream could cause excessive CPU usage in Go Networking's HPACK decoder. An
 attacker could possibly use this to cause a denial of service. This issue
 only affected Ubuntu 22.04 LTS. (CVE-2022-41723)

 Mohammad Thoriq Aziz discovered that Go Networking did not properly
 sanitize some text nodes. An attacker could possibly use this to execute
 arbitrary code. This issue only affected Ubuntu 22.04 LTS. (CVE-2023-3978)

 Sean Ng discovered an error in Go Networking's HTML tag handling. An
 attacker could possibly use this to cause a denial of service.
 (CVE-2025-22872)

 Guido Vranken and Jakub Ciolek discovered that a maliciously crafted HTML
 document could exhaust system resources on servers using Go Networking. An
 attacker could possibly use this to cause a denial of service.
 (CVE-2025-47911)

 Guido Vranken discovered that a maliciously crafted HTML document could put
 servers using Go Networking into an infinite loop. An attacker could
 possibly use this to cause a denial of service. (CVE-2025-58190)");

  script_tag(name:"affected", value:"'adsys, juju-core, lxd' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-github-lxc-lxd-dev", ver:"2.0.11-0ubuntu1~16.04.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"juju", ver:"2.3.7-0ubuntu0.16.04.1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"juju-2.0", ver:"2.3.7-0ubuntu0.16.04.1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc2", ver:"2.0.11-0ubuntu1~16.04.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"2.0.11-0ubuntu1~16.04.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"2.0.11-0ubuntu1~16.04.4+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"2.0.11-0ubuntu1~16.04.4+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"lxd", ver:"3.0.3-0ubuntu1~18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-client", ver:"3.0.3-0ubuntu1~18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxd-tools", ver:"3.0.3-0ubuntu1~18.04.2+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"adsys", ver:"0.9.2~20.04.2ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"adsys-windows", ver:"0.9.2~20.04.2ubuntu0.1+esm1", rls:"UBUNTU20.04 LTS"))) {
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
