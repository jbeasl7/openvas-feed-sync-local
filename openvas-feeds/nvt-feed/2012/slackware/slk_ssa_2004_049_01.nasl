# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53944");
  script_cve_id("CVE-2003-0985", "CVE-2004-0077");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2004-049-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-049-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.541911");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Kernel' package(s) announced via the SSA:2004-049-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernels are available for Slackware 9.1 and -current to fix
a bounds-checking problem in the kernel's mremap() call which
could be used by a local attacker to gain root privileges.
Please note that this is not the same issue as CAN-2003-0985
which was fixed in early January.

The kernels in Slackware 8.1 and 9.0 that were updated in
January are not vulnerable to this new issue because the patch
from Solar Designer that was used to fix the CAN-2003-0985 bugs
also happened to fix the problem that was discovered later.

Sites running Slackware 9.1 or -current should upgrade to a
new kernel. After installing the new kernel, be sure to run
'lilo'.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Wed Feb 18 03:44:42 PST 2004
patches/kernels/: Recompiled to fix another bounds-checking error in
 the kernel mremap() code. (this is not the same issue that was fixed
 on Jan 6) This bug could be used by a local attacker to gain root
 privileges. Sites should upgrade to a new kernel. After installing
 the new kernel, be sure to run 'lilo'.
 For more details, see:
 [link moved to references]
 Thanks to Paul Starzetz for finding and researching this issue.
 (* Security fix *)
patches/packages/kernel-ide-2.4.24-i486-2.tgz: Patched, recompiled.
 (* Security fix *)
patches/packages/kernel-source-2.4.24-noarch-2.tgz: Patched the kernel
 source with a fix for the mremap() problem from Solar Designer, and
 updated the Speakup driver (not pre-applied).
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'Kernel' package(s) on Slackware 9.1, Slackware current.");

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

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.24-i486-2", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.24-noarch-2", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.24-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.24-noarch-2", rls:"SLKcurrent"))) {
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
