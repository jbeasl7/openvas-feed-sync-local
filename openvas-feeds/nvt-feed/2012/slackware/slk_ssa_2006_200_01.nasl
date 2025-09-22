# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57174");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2006-200-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-200-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.544288");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Samba' package(s) announced via the SSA:2006-200-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Samba packages are available for Slackware 10.0, 10.1, 10.2,
and -current.

In Slackware 10.0, 10.1, and 10.2, Samba was evidently picking up
the libdm.so.0 library causing a Samba package issued primarily as
a security patch to suddenly require a library that would only be
present on the machine if the xfsprogs package (from the A series
but marked 'optional') was installed. Sorry -- this was not
intentional, though I do know that I'm taking the chance of this
kind of issue when trying to get security related problems fixed
quickly (hopefully balanced with reasonable testing), and when the
fix is achieved by upgrading to a new version rather than with the
smallest patch possible to fix the known issue. However, I tend
to trust that by following upstream sources as much as possible
I'm also fixing some problems that aren't yet public.

So, all of the 10.0, 10.1, and 10.2 packages have been rebuilt
on systems without the dm library, and should be able to directly
upgrade older samba packages without additional requirements.
Well, unless they are also under /patches. ,-)

All the packages (including -current) have been patched with a
fix from Samba's CVS for some reported problems with winbind.
Thanks to Mikhail Kshevetskiy for pointing me to the patch.

I realize these packages don't really fix security issues, but
they do fix security patch packages that are less than a couple
of days old, so it seems prudent to notify slackware-security
(and any subscribed lists) again. Sorry if it's noise...


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/samba-3.0.23-i486-2_slack10.2.tgz:
 Patched a problem in nsswitch/wins.c that caused crashes in the wins
 and/or winbind libraries.
 Thanks to Mikhail Kshevetskiy for pointing out the issue and offering
 a reference to the patch in Samba's source repository.
 Also, this version of Samba evidently created a new dependency on libdm.so
 (found in the xfsprogs package in non -current Slackware versions). This
 additional dependency was not intentional, and has been corrected.
+--------------------------+");

  script_tag(name:"affected", value:"'Samba' package(s) on Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware current.");

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

if(release == "SLK10.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.0", rls:"SLK10.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.1", rls:"SLK10.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"samba", ver:"3.0.23-i486-2", rls:"SLKcurrent"))) {
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
