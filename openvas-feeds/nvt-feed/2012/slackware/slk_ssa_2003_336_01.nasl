# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53877");
  script_cve_id("CVE-2003-0961");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2003-336-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-336-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.718266");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Kernel' package(s) announced via the SSA:2003-336-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernels are available for Slackware 9.1 and -current. These
have been upgraded to Linux kernel version 2.4.23, which fixes a
bug in the kernel's do_brk() function that could be exploited to
gain root privileges. These updated kernels and modules should be
installed by any sites running a 2.4 kernel earlier than 2.4.23.
Linux 2.0 and 2.2 kernels are not vulnerable.

More details about the Apache issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Mon Dec 1 21:36:30 PST 2003
patches/kernels/: Upgraded to Linux 2.4.23. This fixes a bug in the
 kernel's do_brk() function which a local user could exploit to gain
 root privileges. For more details, see:
 [link moved to references]
 Sites should upgrade to the 2.4.23 kernel and kernel modules. After
 installing the new kernel, be sure to run 'lilo'.
 (* Security fix *)
patches/packages/alsa-driver-0.9.8-i486-1.tgz: Upgraded to
 alsa-driver-0.9.8, compiled against linux-2.4.23.
patches/packages/alsa-lib-0.9.8-i486-1.tgz: Upgraded to alsa-lib-0.9.8.
patches/packages/alsa-oss-0.9.8-i486-1.tgz: Upgraded to alsa-oss-0.9.8.
patches/packages/alsa-utils-0.9.8-i486-1.tgz: Upgraded to
 alsa-utils-0.9.8.
patches/packages/kernel-ide-2.4.23-i486-1.tgz: Upgraded bare.i kernel
 package to Linux 2.4.23.
patches/packages/kernel-modules-2.4.23-i486-1.tgz: Upgraded to Linux
 2.4.23 kernel modules.
patches/packages/kernel-source-2.4.23-noarch-2.tgz: Upgraded to Linux
 2.4.23 kernel source, with XFS and Speakup patches included (but not
 pre-applied).
patches/packages/kernel-modules-xfs/alsa-driver-xfs-0.9.8-i486-1.tgz:
 Upgraded to alsa-driver-0.9.8, compiled against linux-2.4.23-xfs.
patches/packages/kernel-modules-xfs/kernel-modules-xfs-2.4.23-i486-1.tgz:
 Upgraded to Linux 2.4.23 kernel modules for the xfs.s (XFS patched)
 kernel.
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

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver", ver:"0.9.8-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver-xfs", ver:"0.9.8-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-lib", ver:"0.9.8-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-oss", ver:"0.9.8-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-utils", ver:"0.9.8-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.23-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.23-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-xfs", ver:"2.4.23-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.23-noarch-2", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver", ver:"0.9.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver-xfs", ver:"0.9.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-lib", ver:"0.9.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-oss", ver:"0.9.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-utils", ver:"0.9.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.23-i386-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.23-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.23-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-xfs", ver:"2.4.23-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.23-noarch-2", rls:"SLKcurrent"))) {
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
