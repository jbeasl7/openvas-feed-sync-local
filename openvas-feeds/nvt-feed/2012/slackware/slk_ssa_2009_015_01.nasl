# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63229");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2009-015-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2009-015-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.382512");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SSA:2009-015-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated bind packages are available for Slackware 10.2 and 11.0 to address a
load problem. It was reported that the initial build of these updates
complained that the Linux capability module was not present and would refuse
to load. It was determined that the packages which were compiled on 10.2
and 11.0 systems running 2.6 kernels, and although the installed kernel
headers are from 2.4.x, it picked up on this resulting in packages that
would only run under 2.4 kernels. These new packages address the issue.

As always, any problems noted with update patches should be reported to
security@slackware.com, and we will do our best to address them as quickly as
possible.


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
patches/packages/bind-9.3.6_P1-i486-2_slack11.0.tgz:
 Recompiled. The -1_slack11.0 package was compiled on a Slackware 11.0
 system running a 2.6.x kernel, and this caused problems for machines running
 the default 2.4.33.3 kernel. This package should run correctly.
+--------------------------+");

  script_tag(name:"affected", value:"'bind' package(s) on Slackware 10.2, Slackware 11.0.");

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

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.3.6_P1-i486-2_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"bind", ver:"9.3.6_P1-i486-2_slack11.0", rls:"SLK11.0"))) {
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
