# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841057");
  script_tag(name:"creation_date", value:"2012-06-28 05:07:06 +0000 (Thu, 28 Jun 2012)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1463-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU11\.04");

  script_xref(name:"Advisory-ID", value:"USN-1463-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1463-5");
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-1463-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1016386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unity-2d' package(s) announced via the USN-1463-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1463-2 fixed a bug in Unity 2D exposed by a recent Firefox update. It
was discovered that the issue was only partially fixed on Ubuntu 11.04.
When Thunderbird was started from the launcher, Thunderbird was still
unable to obtain pointer grabs under certain conditions. This update fixes
the problem.

Original advisory details:

 USN-1463-1 fixed vulnerabilities in Firefox. The Firefox update exposed a
 bug in Unity 2D which resulted in Firefox being unable to obtain pointer
 grabs in order to open popup menus. This update fixes the problem.");

  script_tag(name:"affected", value:"'unity-2d' package(s) on Ubuntu 11.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"unity-2d-launcher", ver:"3.8.4.1-0ubuntu1.2", rls:"UBUNTU11.04"))) {
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
