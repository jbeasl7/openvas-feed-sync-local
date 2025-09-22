# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57712");
  script_cve_id("CVE-2006-6169", "CVE-2006-6235");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2006-340-01b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|10\.2|11\.0|9\.0|9\.1)");

  script_xref(name:"Advisory-ID", value:"SSA:2006-340-01b");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2006&m=slackware-security.558418");
  script_xref(name:"URL", value:"http://lists.gnupg.org/pipermail/gnupg-announce/2006q4/000246.html");
  script_xref(name:"URL", value:"http://lists.gnupg.org/pipermail/gnupg-announce/2006q4/000491.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg' package(s) announced via the SSA:2006-340-01b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hello,

As many people have pointed out, the last advisory (SSA:2006-340-01)
was not signed with the usual Slackware Security Team key
(fingerprint 40102233). I did some reconfiguration on the box that
does the distribution signing and it had some unintended
side-effects. :-/ Several CHECKSUMS.md5.asc files were also signed
with the wrong key.

The affected CHECKSUMS.md5 files have been resigned and uploaded, and
this announcement has also been signed (and verified :-) using the
usual primary Slackware signing key.

Also, it was noticed that the URL given to lists.gnupg.org was either
incorrect or has changed since the advisory was issued. This error
has also been corrected.

Sorry for any confusion.

Pat

Corrected advisory follows:

+-----------+

[slackware-security] gnupg (SSA:2006-340-01)

New gnupg packages are available for Slackware 9.0, 9.1, 10.0, 10.1,
10.2, and 11.0 to fix security issues.

More details about the issues may be found here:
 [links moved to references]


Here are the details from the Slackware 11.0 ChangeLog:
+--------------------------+
patches/packages/gnupg-1.4.6-i486-1_slack11.0.tgz:
 Upgraded to gnupg-1.4.6. This release fixes a severe and exploitable
 bug in earlier versions of gnupg. All gnupg users should update to the
 new packages as soon as possible. For details, see the information
 concerning CVE-2006-6235 posted on lists.gnupg.org:
 [link moved to references]
 The CVE entry for this issue may be found here:
 [link moved to references]
 This update also addresses a more minor security issue possibly
 exploitable when GnuPG is used in interactive mode. For more information
 about that issue, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'gnupg' package(s) on Slackware 9.0, Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware 10.2, Slackware 11.0.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i486-1_slack10.0", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i486-1_slack10.1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i486-1_slack10.2", rls:"SLK10.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i386-1_slack9.0", rls:"SLK9.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK9.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"gnupg", ver:"1.4.6-i486-1_slack9.1", rls:"SLK9.1"))) {
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
