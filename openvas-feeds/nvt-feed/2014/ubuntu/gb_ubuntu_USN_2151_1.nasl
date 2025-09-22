# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841761");
  script_cve_id("CVE-2014-1493", "CVE-2014-1497", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"creation_date", value:"2014-03-25 04:54:04 +0000 (Tue, 25 Mar 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-19 21:14:56 +0000 (Wed, 19 Mar 2014)");

  script_name("Ubuntu: Security Advisory (USN-2151-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2151-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2151-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1293851");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2151-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij, Jesse Ruderman, Dan
Gohman and Christoph Diehl discovered multiple memory safety issues in
Thunderbird. If a user were tricked in to opening a specially crafted
message with scripting enabled, an attacker could potentially exploit
these to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1493)

Atte Kettunen discovered an out-of-bounds read during WAV file decoding.
If a user had enabled audio, an attacker could potentially exploit this
to cause a denial of service via application crash. (CVE-2014-1497)

Robert O'Callahan discovered a mechanism for timing attacks involving
SVG filters and displacements input to feDisplacementMap. If a user had
enabled scripting, an attacker could potentially exploit this to steal
confidential information across domains. (CVE-2014-1505)

Tyson Smith and Jesse Schwartzentruber discovered an out-of-bounds read
during polygon rendering in MathML. If a user had enabled scripting, an
attacker could potentially exploit this to steal confidential information
across domains. (CVE-2014-1508)

John Thomson discovered a memory corruption bug in the Cairo graphics
library. If a user had a malicious extension installed, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-1509)

Mariusz Mlynski discovered that web content could open a chrome privileged
page and bypass the popup blocker in some circumstances. If a user had
enabled scripting, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1510, CVE-2014-1511)

It was discovered that memory pressure during garbage collection resulted
in memory corruption in some circumstances. If a user had enabled
scripting, an attacker could potentially exploit this to cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1512)

Juri Aedla discovered out-of-bounds reads and writes with TypedArrayObject
in some circumstances. If a user had enabled scripting, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-1513)

George Hotz discovered an out-of-bounds write with TypedArrayObject. If a
user had enabled scripting, an attacker could potentially exploit this to
cause a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2014-1514)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.4.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.4.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.4.0+build1-0ubuntu0.13.10.2", rls:"UBUNTU13.10"))) {
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
