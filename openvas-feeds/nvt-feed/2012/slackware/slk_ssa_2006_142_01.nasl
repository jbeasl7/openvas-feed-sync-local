# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56793");
  script_cve_id("CVE-2005-3193");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2006-142-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-142-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.399813");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tetex' package(s) announced via the SSA:2006-142-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New tetex packages are available for Slackware 10.2 and -current to
fix a possible security issue. teTeX-3.0 incorporates some code from
the xpdf program which has been shown to have various overflows that
could result in program crashes or possibly the execution of arbitrary
code as the teTeX user. This is especially important to consider if
teTeX is being used as part of a printer filter.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 10.2 ChangeLog:
+--------------------------+
patches/packages/tetex-3.0-i486-2_10.2.tgz: Regenerated the etex.fmt files
 with etex, not pdfetex. This is more appropriate since etex is a binary,
 not a link to pdfetex. Thanks to John Breckenridge for reporting the issue.
 Added --disable-a4, and fixed the texconfig for US paper default in the
 build script. Thanks to Marc Benstein and Jingmin Zhou for reporting this.
 Improved /tmp use security.
 Patched a possible security issue in library code borrowed from xpdf that's
 used in pdfetex.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'tetex' package(s) on Slackware 10.2, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"tetex", ver:"3.0-i486-2_10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"tetex", ver:"3.0-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"tetex-doc", ver:"3.0-i486-2", rls:"SLKcurrent"))) {
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
