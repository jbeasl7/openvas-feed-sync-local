# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53937");
  script_cve_id("CVE-2004-0394", "CVE-2004-0424");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2004-119-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-119-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.659586");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2004-119-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 9.1 and -current to
fix security issues. Also available are new kernel modules packages
(including alsa-driver), and a new version of the hotplug package
for Slackware 9.1 containing some fixes for using 2.4.26 (and 2.6.x)
kernel modules.

The most serious of the fixed issues is an overflow in ip_setsockopt(),
which could allow a local attacker to gain root access, or to crash or
reboot the machine. This bug affects 2.4 kernels from 2.4.22 - 2.4.25.
Any sites running one of those kernel versions should upgrade right
away. After installing the new kernel, be sure to run 'lilo'.

More details about the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:
 [links moved to references]


Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Wed Apr 28 10:19:51 PDT 2004
patches/packages/kernel-ide-2.4.26-i486-2.tgz: The first version of this
 package included one of the old 2.4.22 kernels by mistake. Thanks to the
 many people who pointed out this error. Sorry!
 (* Security fix *)
+--------------------------+
Tue Apr 27 15:25:29 PDT 2004
patches/packages/alsa-driver-0.9.8-i486-3.tgz: Recompiled for Linux 2.4.26.
patches/packages/hotplug-2004_01_05-noarch-1.tgz: This adds bugfixes for using
 a 2.6.x kernel, and adds the broken via-ircc module to the hotplug blacklist.
 Note that upgrading the package will not replace an existing blacklist, but
 as far as I can tell there are no ill effects from trying to load via-ircc
 other than the ugly mess on the screen at boot time.
patches/packages/kernel-ide-2.4.26-i486-1.tgz: Upgraded to Linux 2.4.26.
patches/packages/kernel-headers-2.4.26-i386-1.tgz: Upgraded to Linux 2.4.26.
patches/packages/kernel-modules-2.4.26-i486-1.tgz: Upgraded to Linux 2.4.26.
patches/packages/kernel-source-2.4.26-noarch-1.tgz: Upgraded to Linux 2.4.26.
patches/packages/kernels/*: Upgraded to Linux 2.4.26.
 These 2.4.26 kernel upgrades fix:
 an overflow in ip_setsockopt() [CAN-2004-0424]
 a flaw in do_fork() that could lead to a DoS
 an (unexploitable) overflow in panic() [CAN-2004-0394]
 For more details, see:
 [links moved to references]
 (* Security fix *)");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 9.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver", ver:"0.9.8-i486-3", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"hotplug", ver:"2004_01_05-noarch-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.26-i386-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.26-i486-2", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.26-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.26-noarch-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"alsa-driver", ver:"1.0.4-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.4.26-i386-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-ide", ver:"2.4.26-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.4.26-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.4.26-noarch-1", rls:"SLKcurrent"))) {
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
