# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61604");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2008-247-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2008-247-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.369588");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-4.php#4.4.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2008-247-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 10.2 and 11.0 to fix security
issues. These releases are the last to contain PHP 4.4.x, which was upgraded
to version 4.4.9 to fix PCRE issues and other bugs.

Please note that this is the FINAL release of PHP4, and it has already passed
the announced end-of-life. Sites should seriously consider migrating to PHP5
rather than upgrading to php-4.4.9.


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
patches/packages/php-4.4.9-i486-1_slack11.0.tgz:
 Upgraded to php-4.4.9. This upgrades the bundled PCRE library to fix
 security issues, as well as fixing a few other security related bugs.
 See the PHP4 ChangeLog for more details:
 [link moved to references]
 Please note: PHP4 has been officially discontinued since last year, and
 reached the announced EOL on 2008-08-08. Sites should consider migrating
 to a supported release.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 10.2, Slackware 11.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.9-i486-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.9-i486-1_slack11.0", rls:"SLK11.0"))) {
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
