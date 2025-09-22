# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53926");
  script_cve_id("CVE-2004-0488");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2004-154-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2004-154-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2004&m=slackware-security.583808");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod_ssl' package(s) announced via the SSA:2004-154-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mod_ssl packages are available for Slackware 8.1, 9.0, 9.1, and -current
to fix a security issue. The packages were upgraded to mod_ssl-2.8.18-1.3.31
fixing a buffer overflow that may allow remote attackers to execute arbitrary
code via a client certificate with a long subject DN, if mod_ssl is
configured to trust the issuing CA. Web sites running mod_ssl should upgrade
to the new set of apache and mod_ssl packages. There are new PHP packages as
well to fix a Slackware-specific local denial-of-service issue (an additional
Slackware advisory SSA:2004-154-02 has been issued for PHP).

More details about the mod_ssl issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]

Here are the details from the Slackware 9.1 ChangeLog:
+--------------------------+
Wed Jun 2 11:28:17 PDT 2004
patches/packages/mod_ssl-2.8.18_1.3.31-i486-1.tgz: Upgraded to
 mod_ssl-2.8.18-1.3.31. This fixes a buffer overflow that may allow remote
 attackers to execute arbitrary code via a client certificate with a long
 subject DN, if mod_ssl is configured to trust the issuing CA:
 *) Fix buffer overflow in 'SSLOptions +FakeBasicAuth' implementation
 if the Subject-DN in the client certificate exceeds 6KB in length.
 For more details, see:
 [link moved to references]
 (* Security fix *)
 Other changes: Make the sample keys .new so as not to overwrite existing
 server keys. However, any existing mod_ssl package will have these listed
 as non-config files, and will still remove and replace these upon upgrade.
 You'll have to save your config files one more time... sorry).
+--------------------------+");

  script_tag(name:"affected", value:"'mod_ssl' package(s) on Slackware 8.1, Slackware 9.0, Slackware 9.1, Slackware current.");

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

if(release == "SLK8.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.31-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.18_1.3.31-i386-1", rls:"SLK8.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.6-i386-1", rls:"SLK8.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.31-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.18_1.3.31-i386-1", rls:"SLK9.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.6-i386-1", rls:"SLK9.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.31-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.18_1.3.31-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.6-i486-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"apache", ver:"1.3.31-i486-2", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mod_ssl", ver:"2.8.18_1.3.31-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"4.3.6-i486-4", rls:"SLKcurrent"))) {
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
