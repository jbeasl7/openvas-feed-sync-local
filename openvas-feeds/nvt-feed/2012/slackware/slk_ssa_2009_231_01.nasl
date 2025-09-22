# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64770");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2009-231-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK12\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2009-231-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.449266");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2009-231-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a followup to the SSA:2009-230-01 advisory noting some errata.

The generic SMP kernel update for Slackware 12.2 was built using the
.config for a huge kernel, not a generic one. The kernel previously
published as kernel-generic-smp and in the gemsmp.s directory works
and is secure, but is larger than it needs to be. It has been
replaced in the Slackware 12.2 patches with a generic SMP kernel.

A new svgalib_helper package (compiled for a 2.6.27.31 kernel) was
added to the Slackware 12.2 /patches.

An error was noticed in the SSA:2009-230-01 advisory concerning the
packages for Slackware -current 32-bit. The http links given refer to
packages with a -1 build version. The actual packages have a build
number of -2.


Here are the details from the Slackware 12.2 ChangeLog:
+--------------------------+
patches/packages/linux-2.6.27.31/kernel-modules-smp-2.6.27.31_smp-i686-2.tgz:
 Rebuilt the modules using the config-generic-smp-2.6.27.31-smp .config.
patches/packages/linux-2.6.27.31/kernel-generic-smp-2.6.27.31_smp-i686-2.tgz:
 Fixed the .config to use config-generic-smp-2.6.27.31-smp.
 The config-generic-huge-2.6.27.31-smp was mistakenly used for build -1.
 Thanks to Chuck56 for the report.
patches/packages/linux-2.6.27.31/kernel-source-2.6.27.31_smp-noarch-2.tgz:
 Changed the included .config to the config-generic-smp-2.6.27.31-smp version.
patches/packages/svgalib_helper-1.9.25_2.6.27.31-i486-1_slack12.2.tgz:
 Recompiled for 2.6.27.31.
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 12.2.");

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

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.27.31_smp-i686-2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.27.31_smp-i686-2", rls:"SLK12.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.27.31_smp-noarch-2", rls:"SLK12.2"))) {
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
