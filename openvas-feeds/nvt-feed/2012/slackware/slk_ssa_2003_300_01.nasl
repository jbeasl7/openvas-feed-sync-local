# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53879");
  script_cve_id("CVE-2003-0793", "CVE-2003-0794");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2003-300-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-300-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.388783");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdm' package(s) announced via the SSA:2003-300-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GDM is the GNOME Display Manager, and is commonly used to provide
a graphical login for local users.

Upgraded gdm packages are available for Slackware 9.0, 9.1,
and -current. These fix two vulnerabilities which could allow a local
user to crash or freeze gdm, preventing access to the machine until a
reboot. Sites using gdm should upgrade, especially sites such as
computer labs that use gdm to provide public or semi-public access.

More details about these issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [links moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Wed Oct 22 12:10:11 PDT 2003
patches/packages/gdm-2.4.4.5-i486-1.tgz: Upgraded to gdm-2.4.4.5. This
 fixes a bug which can allow a local user to crash gdm, preventing
 access until the machine is rebooted.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gdm' package(s) on Slackware 9.0, Slackware 9.1, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gdm", ver:"2.4.1.7-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gdm", ver:"2.4.4.5-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"gdm", ver:"2.4.4.5-i486-1", rls:"SLKcurrent"))) {
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
