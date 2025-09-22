# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843167");
  script_cve_id("CVE-2016-6252", "CVE-2017-2616");
  script_tag(name:"creation_date", value:"2017-05-17 04:53:04 +0000 (Wed, 17 May 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-21 13:49:05 +0000 (Fri, 21 Sep 2018)");

  script_name("Ubuntu: Security Advisory (USN-3276-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3276-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3276-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1690820");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadow' package(s) announced via the USN-3276-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3276-1 intended to fix a vulnerability in su. The solution introduced
a regression in su signal handling. This update modifies the security fix.
We apologize for the inconvenience.

Original advisory details:

 Sebastian Krahmer discovered integer overflows in shadow utilities.
 A local attacker could possibly cause them to crash or potentially
 gain privileges via crafted input. (CVE-2016-6252)

 Tobias Stockmann discovered a race condition in su. A local
 attacker could cause su to send SIGKILL to other processes with
 root privileges. (CVE-2017-2616)");

  script_tag(name:"affected", value:"'shadow' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"login", ver:"1:4.1.5.1-1ubuntu9.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passwd", ver:"1:4.1.5.1-1ubuntu9.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uidmap", ver:"1:4.1.5.1-1ubuntu9.5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"login", ver:"1:4.2-3.1ubuntu5.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passwd", ver:"1:4.2-3.1ubuntu5.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uidmap", ver:"1:4.2-3.1ubuntu5.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"login", ver:"1:4.2-3.2ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passwd", ver:"1:4.2-3.2ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uidmap", ver:"1:4.2-3.2ubuntu1.16.10.2", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"login", ver:"1:4.2-3.2ubuntu1.17.04.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"passwd", ver:"1:4.2-3.2ubuntu1.17.04.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uidmap", ver:"1:4.2-3.2ubuntu1.17.04.2", rls:"UBUNTU17.04"))) {
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
