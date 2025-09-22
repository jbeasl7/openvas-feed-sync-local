# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0438");
  script_cve_id("CVE-2014-8761", "CVE-2014-8762", "CVE-2014-8763", "CVE-2014-8764");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0438)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0438");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0438.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/10/16/9");
  script_xref(name:"URL", value:"http://www.freelists.org/post/dokuwiki/Fwd-Dokuwiki-maybe-security-issue-Null-byte-poisoning-in-LDAP-authentication");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14252");
  script_xref(name:"URL", value:"https://www.dokuwiki.org/changes#release_2014-09-29_hrun");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dokuwiki' package(s) announced via the MGASA-2014-0438 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"inc/template.php in DokuWiki before 2014-05-05a only checks for access to the
root namespace, which allows remote attackers to access arbitrary images via a
media file details ajax call (CVE-2014-8761).

The ajax_mediadiff function in DokuWiki before 2014-05-05a allows remote
attackers to access arbitrary images via a crafted namespace in the ns
parameter (CVE-2014-8762).

DokuWiki before 2014-05-05b, when using Active Directory for LDAP
authentication, allows remote attackers to bypass authentication via a
password starting with a null (\0) character and a valid user name, which
triggers an unauthenticated bind (CVE-2014-8763).

DokuWiki 2014-05-05a and earlier, when using Active Directory for LDAP
authentication, allows remote attackers to bypass authentication via a user
name and password starting with a null (\0) character, which triggers an
anonymous bind (CVE-2014-8764).");

  script_tag(name:"affected", value:"'dokuwiki' package(s) on Mageia 3, Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"dokuwiki", rpm:"dokuwiki~20140929~1.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"dokuwiki", rpm:"dokuwiki~20140929~1.1.mga4", rls:"MAGEIA4"))) {
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
