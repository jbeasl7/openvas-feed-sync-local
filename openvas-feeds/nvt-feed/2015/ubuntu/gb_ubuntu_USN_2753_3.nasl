# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842478");
  script_tag(name:"creation_date", value:"2015-10-06 10:43:25 +0000 (Tue, 06 Oct 2015)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2753-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2753-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2753-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1501491");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the USN-2753-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2753-1 fixed a vulnerability in LXC. The update caused a regression
that prevented some containers from starting. This regression only
affected containers that had a path that contained a '/./' directory
specified as a bind mount target in their configuration file. This
update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 Roman Fiedler discovered a directory traversal flaw in lxc-start. A local
 attacker with access to an LXC container could exploit this flaw to run
 programs inside the container that are not confined by AppArmor or expose
 unintended files in the host to the container.");

  script_tag(name:"affected", value:"'lxc' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"liblxc1", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc-dev", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc-templates", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lxc-tests", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-lxc", ver:"1.0.7-0ubuntu0.7", rls:"UBUNTU14.04 LTS"))) {
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
