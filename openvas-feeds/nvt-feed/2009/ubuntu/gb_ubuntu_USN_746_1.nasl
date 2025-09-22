# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63746");
  script_cve_id("CVE-2009-0698");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-746-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.10|8\.04\ LTS|8\.10)");

  script_xref(name:"Advisory-ID", value:"USN-746-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-746-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/322834");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xine-lib' package(s) announced via the USN-746-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the 4xm demuxer in xine-lib did not correctly handle
a large current_track value in a 4xm file, resulting in an integer
overflow. If a user or automated system were tricked into opening a
specially crafted 4xm movie file, an attacker could crash xine-lib or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-0698)

USN-710-1 provided updated xine-lib packages to fix multiple security
vulnerabilities. The security patch to fix CVE-2008-5239 introduced a
regression causing some media files to be unplayable. This update corrects
the problem. We apologize for the inconvenience.

Original advisory details:
 It was discovered that the input handlers in xine-lib did not correctly
 handle certain error codes, resulting in out-of-bounds reads and heap-
 based buffer overflows. If a user or automated system were tricked into
 opening a specially crafted file, stream, or URL, an attacker could
 execute arbitrary code as the user invoking the program. (CVE-2008-5239)");

  script_tag(name:"affected", value:"'xine-lib' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine-main1", ver:"1.1.1+ubuntu2-7.11", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.7-1ubuntu1.5", rls:"UBUNTU7.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.11.1-1ubuntu3.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxine1", ver:"1.1.15-0ubuntu3.2", rls:"UBUNTU8.10"))) {
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
