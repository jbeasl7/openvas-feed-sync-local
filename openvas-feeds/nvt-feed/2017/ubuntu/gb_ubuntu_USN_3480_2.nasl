# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843368");
  script_cve_id("CVE-2017-14177", "CVE-2017-14180");
  script_tag(name:"creation_date", value:"2017-11-21 06:31:03 +0000 (Tue, 21 Nov 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-15 13:21:09 +0000 (Thu, 15 Feb 2018)");

  script_name("Ubuntu: Security Advisory (USN-3480-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|17\.04|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3480-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3480-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1726372");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1732518");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-3480-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3480-1 fixed vulnerabilities in Apport. The fix for CVE-2017-14177
introduced a regression in the ability to handle crashes for users that
configured their systems to use the Upstart init system in Ubuntu 16.04
LTS and Ubuntu 17.04. The fix for CVE-2017-14180 temporarily disabled
crash forwarding to containers. This update addresses the problems.

We apologize for the inconvenience.

Original advisory details:

 Sander Bos discovered that Apport incorrectly handled core dumps for setuid
 binaries. A local attacker could use this issue to perform a denial of service
 via resource exhaustion or possibly gain root privileges. (CVE-2017-14177)

 Sander Bos discovered that Apport incorrectly handled core dumps for processes
 in a different PID namespace. A local attacker could use this issue to perform
 a denial of service via resource exhaustion or possibly gain root privileges.
 (CVE-2017-14180)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.1-0ubuntu2.13", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.4-0ubuntu4.8", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.20.7-0ubuntu3.5", rls:"UBUNTU17.10"))) {
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
