# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53962");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2005-085-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.0|10\.1|9\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2005-085-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2005&m=slackware-security.635646");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Mozilla");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla/Firefox/Thunderbird' package(s) announced via the SSA:2005-085-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Mozilla packages are available for Slackware 9.1, 10.0, 10.1, and -current
to fix various security issues and bugs. See the Mozilla site for a complete
list of the issues patched:

 [link moved to references]

Also updated are Firefox and Thunderbird in Slackware -current, and GAIM in
Slackware 9.1, 10.0, and 10.1 (which uses the Mozilla NSS libraries).

New versions of the mozilla-plugins symlink creation package are also out for
Slackware 9.1, 10.0, and 10.1.

Just a little note on Slackware security -- I believe the state of Slackware
right now is quite secure. I know there have been issues announced and fixed
elsewhere, and I am assessing the reality of them (to be honest, it seems the
level of proof needed to announce a security hole these days has fallen close
to zero -- where are the proof-of-concept exploits?) It is, as always, my
firm intent to keep Slackware as secure as it can possibly be. I'm still
getting back up to speed (and I do not believe that anything exploitable in
real life is being allowed to slide), but I'm continuing to look over the
various reports and would welcome input at security@slackware.com if you feel
anything important has been overlooked and is in need of attention. Please
remember that I do read BugTraq and many other security lists. I am not
asking for duplicates of BugTraq posts unless you have additional proof or
information on the issues, or can explain how an issue affects your own
servers. This will help me to priorite any work that remains to be done.
Thanks in advance for any helpful comments.


Here are the details from the Slackware 10.1 ChangeLog:
+--------------------------+
patches/packages/gaim-1.2.0-i486-1.tgz: Upgraded to gaim-1.2.0 and
 gaim-encryption-2.36 (compiled against mozilla-1.7.6).
patches/packages/mozilla-1.7.6-i486-1.tgz: Upgraded to mozilla-1.7.6.
 Fixes some security issues. Please see mozilla.org for a complete list.
 (* Security fix *)
patches/packages/mozilla-plugins-1.7.6-noarch-1.tgz: Adjusted plugin
 symlinks for Mozilla 1.7.6.
+--------------------------+");

  script_tag(name:"affected", value:"'Mozilla/Firefox/Thunderbird' package(s) on Slackware 9.1, Slackware 10.0, Slackware 10.1, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.6-i486-1", rls:"SLK10.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.6-noarch-1", rls:"SLK10.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.6-i486-1", rls:"SLK10.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.7.6-noarch-1", rls:"SLK10.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.4.4-i486-1", rls:"SLK9.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-plugins", ver:"1.4.4-noarch-1", rls:"SLK9.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"gaim", ver:"1.2.0-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"jre-symlink", ver:"1.0.2-noarch-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla", ver:"1.7.6-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"1.0.2-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-i686-1", rls:"SLKcurrent"))) {
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
