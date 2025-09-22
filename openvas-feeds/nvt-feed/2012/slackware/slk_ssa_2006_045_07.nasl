# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56289");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2006-045-07)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-045-07");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.403774");
  script_xref(name:"URL", value:"http://www.php.net/release_4_4_2.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2006-045-07 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 10.2 and -current to
fix minor security issues.

More details about these issues may be found on the PHP website:

 [link moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/php-4.4.2-i486-1.tgz: Upgraded to php-4.4.2.
 Claims to fix 'a few small security issues'.
 For more information, see:
 [link moved to references]
 (* Security fix *)
patches/packages/php-4.4.2-i486-2.tgz: Rebuilt the package to
 clean up some junk dotfiles that were installed in the /
 directory. Harmless, but sloppy...
 Thanks to Krzysztof Oledzki for pointing this out.
patches/packages/php-4.4.2-i486-3.tgz: Fixed some more bugs from the 4.4.2
 release... hopefully the third time is the charm.
 Replaced PEAR packages for which the 4.4.2 release contained incorrect
 md5sums: Archive_Tar-1.3.1, Console_Getopt-1.2, and HTML_Template_IT-1.1.3.
 (this last one was also not upgraded to the stable version that was released
 on 2005-11-01) Sorry to have delayed the advisories, but these bugs had to
 be fixed first. IMHO, the security issues are of dubious severity anyway,
 or a more aggressive approach would have been taken (though this would likely
 have caused a lot of people to upgrade to the broken -1 or -2 package
 revisions, so anyone who didn't know about this until now was probably saved
 a hassle.)
 Upgraded other PEAR modules to HTTP-1.4.0, Net_SMTP-1.2.8, and XML_RPC-1.4.5.
 Thanks again to Krzysztof Oledzki for the bug report.
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.2-i486-3", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.4.2-i486-3", rls:"SLKcurrent"))) {
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
