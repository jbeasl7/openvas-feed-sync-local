# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840901");
  script_cve_id("CVE-2011-3152", "CVE-2011-3154");
  script_tag(name:"creation_date", value:"2012-02-21 13:30:18 +0000 (Tue, 21 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1284-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|11\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1284-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1284-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/933225");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update-manager' package(s) announced via the USN-1284-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1284-1 fixed vulnerabilities in Update Manager. One of the fixes
introduced a regression for Kubuntu users attempting to upgrade to a newer
Ubuntu release. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 David Black discovered that Update Manager incorrectly extracted the
 downloaded upgrade tarball before verifying its GPG signature. If a remote
 attacker were able to perform a machine-in-the-middle attack, this flaw could
 potentially be used to replace arbitrary files. (CVE-2011-3152)

 David Black discovered that Update Manager created a temporary directory
 in an insecure fashion. A local attacker could possibly use this flaw to
 read the XAUTHORITY file of the user performing the upgrade.
 (CVE-2011-3154)

 This update also adds a hotfix to Update Notifier to handle cases where the
 upgrade is being performed from CD media.");

  script_tag(name:"affected", value:"'update-manager' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.134.11.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.142.23.2", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.150.5.2", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.152.25.8", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.87.33", rls:"UBUNTU8.04 LTS"))) {
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
