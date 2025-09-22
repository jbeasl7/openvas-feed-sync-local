# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58228");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2007-110-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK11\.0");

  script_xref(name:"Advisory-ID", value:"SSA:2007-110-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2007&m=slackware-security.438405");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x11-6' package(s) announced via the SSA:2007-110-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A new x11-6.9.0-i486-14_slack11.0.tgz patch is available for Slackware 11.0 to
fix the inadvertent inclusion of two old fontconfig binaries. Installing the
original fontconfig patch followed by the original x11 patch would cause
fc-cache and fc-list to be overwritten by old versions, breaking fontconfig.

To fix the issue, reinstall the fontconfig patch. The x11 package has been
updated so that installation will not be order-specific for anyone fetching
the patches now.

Sorry for the inconvenience.


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
patches/packages/x11-6.9.0-i486-14_slack11.0.tgz:
 Removed old versions of fc-cache and fc-list.
 Somehow a couple of old fontconfig binaries snuck into this package, and
 prevent fc-cache from working properly at boot (or any other time).
 If you've already installed these upgrades, reinstalling the fontconfig
 package will fix the issue. If you do that, there's no need to reinstall
 this new x11 package -- it's been fixed so that there's no longer a problem
 with the package install order (and because those fc-* binaries didn't
 belong there). Sorry for any inconvenience...
 Thanks to Petri Kaukasoina for pointing this out.
 (* Fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'x11-6' package(s) on Slackware 11.0.");

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

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"x11", ver:"6.9.0-i486-14_slack11.0", rls:"SLK11.0"))) {
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
