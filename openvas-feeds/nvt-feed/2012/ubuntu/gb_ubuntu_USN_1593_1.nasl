# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841169");
  script_cve_id("CVE-2012-0212", "CVE-2012-2240", "CVE-2012-2241", "CVE-2012-2242", "CVE-2012-3500");
  script_tag(name:"creation_date", value:"2012-10-03 03:54:12 +0000 (Wed, 03 Oct 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1593-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1593-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1593-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'devscripts' package(s) announced via the USN-1593-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Raphael Geissert discovered that the debdiff.pl tool incorrectly handled
shell metacharacters. If a user or automated system were tricked into
processing a specially crafted filename, a remote attacher could possibly
execute arbitrary code. (CVE-2012-0212)

Raphael Geissert discovered that the dscverify tool incorrectly escaped
arguments to external commands. If a user or automated system were tricked
into processing specially crafted files, a remote attacher could possibly
execute arbitrary code. (CVE-2012-2240)

Raphael Geissert discovered that the dget tool incorrectly performed input
validation. If a user or automated system were tricked into processing
specially crafted files, a remote attacher could delete arbitrary files.
(CVE-2012-2241)

Raphael Geissert discovered that the dget tool incorrectly escaped
arguments to external commands. If a user or automated system were tricked
into processing specially crafted files, a remote attacher could possibly
execute arbitrary code. This issue only affected Ubuntu 10.04 LTS and
Ubuntu 11.04. (CVE-2012-2242)

Jim Meyering discovered that the annotate-output tool incorrectly handled
temporary files. A local attacker could use this flaw to alter files being
processed by the annotate-output tool. On Ubuntu 11.04 and later, this
issue was mitigated by the Yama kernel symlink restrictions.
(CVE-2012-3500)");

  script_tag(name:"affected", value:"'devscripts' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.10.61ubuntu5.3", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.10.69ubuntu2.2", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.11.1ubuntu3.2", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"devscripts", ver:"2.11.6ubuntu1.4", rls:"UBUNTU12.04 LTS"))) {
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
