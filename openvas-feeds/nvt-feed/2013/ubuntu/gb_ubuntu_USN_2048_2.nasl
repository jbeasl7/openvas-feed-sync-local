# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841660");
  script_tag(name:"creation_date", value:"2013-12-17 06:40:08 +0000 (Tue, 17 Dec 2013)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2048-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2048-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2048-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1258366");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-2048-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2048-1 fixed a vulnerability in curl. The security fix uncovered a bug
in the curl command line tool which resulted in the --insecure (-k) option
not working as intended. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Scott Cantor discovered that libcurl incorrectly verified CN and SAN name
 fields when digital signature verification was disabled. When libcurl is
 being used in this uncommon way by specific applications, an attacker could
 exploit this to perform a machine-in-the-middle attack to view sensitive
 information or alter encrypted communications.");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.19.7-1ubuntu1.5", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.22.0-3ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.27.0-1ubuntu1.6", rls:"UBUNTU12.10"))) {
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
