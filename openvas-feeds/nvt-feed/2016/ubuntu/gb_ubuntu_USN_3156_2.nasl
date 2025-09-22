# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842994");
  script_tag(name:"creation_date", value:"2016-12-17 04:31:20 +0000 (Sat, 17 Dec 2016)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3156-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.10");

  script_xref(name:"Advisory-ID", value:"USN-3156-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3156-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1649959");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt' package(s) announced via the USN-3156-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3156-1 fixed vulnerabilities in APT. It also caused a bug in
unattended-upgrades on that may require manual intervention to repair.

Users on Ubuntu 16.10 should run the following commands at a
terminal:

sudo dpkg --configure --pending
sudo apt-get -f install

This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Jann Horn discovered that APT incorrectly handled InRelease files.
 If a remote attacker were able to perform a machine-in-the-middle attack,
 this flaw could potentially be used to install altered packages.");

  script_tag(name:"affected", value:"'apt' package(s) on Ubuntu 16.10.");

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

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"apt", ver:"1.3.3", rls:"UBUNTU16.10"))) {
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
