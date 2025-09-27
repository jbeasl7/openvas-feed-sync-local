# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7773.1");
  script_cve_id("CVE-2025-31176", "CVE-2025-31177", "CVE-2025-31178", "CVE-2025-31179", "CVE-2025-31180", "CVE-2025-31181", "CVE-2025-3359");
  script_tag(name:"creation_date", value:"2025-09-26 04:04:47 +0000 (Fri, 26 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-07 13:15:43 +0000 (Mon, 07 Apr 2025)");

  script_name("Ubuntu: Security Advisory (USN-7773-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7773-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7773-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnuplot' package(s) announced via the USN-7773-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ChenYiFan Liu discovered that Gnuplot did not correctly handle certain
memory operations. An attacker could possibly use this issue to cause a
denial of service. (CVE-2025-3359, CVE-2025-31178, CVE-2025-31179,
CVE-2025-31181)

ChenYiFan Liu discovered that Gnuplot did not correctly handle certain
memory operations. An attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 18.04 LTS, Ubuntu 20.04
LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Ubuntu 25.04. (CVE-2025-31176,
CVE-2025-31180)

ChenYiFan Liu discovered that Gnuplot did not correctly handle certain
memory operations. An attacker could possibly use this issue to execute
arbitrary code or cause a denial of service. This issue only affected
Ubuntu 18.04 LTS, Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS,
Ubuntu 25.04. (CVE-2025-31177)");

  script_tag(name:"affected", value:"'gnuplot' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"4.6.4-2ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"4.6.6-3ubuntu0.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"5.2.2+dfsg1-2ubuntu1+esm2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"5.2.8+dfsg1-2ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"5.4.2+dfsg2-2ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"6.0.0+dfsg1-1ubuntu3+esm1", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnuplot", ver:"6.0.2+dfsg1-1ubuntu0.1", rls:"UBUNTU25.04"))) {
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
