# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53898");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-141-06)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK9\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2003-141-06");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.340559");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quotacheck' package(s) announced via the SSA:2003-141-06 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An upgraded sysvinit package is available which fixes a problem with
the use of quotacheck in /etc/rc.d/rc.M. The original version of
rc.M calls quotacheck like this:

 echo 'Checking filesystem quotas: /sbin/quotacheck -avugM'
 /sbin/quotacheck -avugM

The 'M' option is wrong. This causes the filesystem to be remounted,
and in the process any mount flags such as nosuid, nodev, noexec,
and the like, will be reset. The correct option to use here is 'm',
which does not attempt to remount the partition:

 echo 'Checking filesystem quotas: /sbin/quotacheck -avugm'
 /sbin/quotacheck -avugm

We recommend sites using file system quotas upgrade to this new package,
or edit /etc/rc.d/rc.M accordingly.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Tue May 20 20:13:09 PDT 2003
patches/packages/sysvinit-2.84-i386-26.tgz: Use option M, not m, for quotacheck.
 Otherwise, the partition might be remounted losing flags like nosuid,nodev,
 noexec. Thanks to Jem Berkes for pointing this out.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'quotacheck' package(s) on Slackware 9.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"sysvinit", ver:"2.84-i386-26", rls:"SLK9.0"))) {
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
