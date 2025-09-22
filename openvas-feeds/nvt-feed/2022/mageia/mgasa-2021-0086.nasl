# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0086");
  script_cve_id("CVE-2020-35475", "CVE-2020-35477", "CVE-2020-35479", "CVE-2020-35480");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-21 16:41:08 +0000 (Mon, 21 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0086");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0086.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27781");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-December/000268.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2020-December/000269.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4816");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2021-0086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In MediaWiki before 1.31.11, the messages userrights-expiry-current and
userrights-expiry-none can contain raw HTML. XSS can happen when a user visits
Special:UserRights but does not have rights to change all userrights, and the
table on the left side has unchangeable groups in it. The right column with
the changeable groups is not affected and is escaped correctly
(CVE-2020-35475).

MediaWiki before 1.31.11 blocks legitimate attempts to hide log entries in
some situations. If one sets MediaWiki:Mainpage to Special:MyLanguage/Main
Page, visits a log entry on Special:Log, and toggles the 'Change visibility of
selected log entries' checkbox (or a tags checkbox) next to it, there is a
redirection to the main page's action=historysubmit instead of the desired
behavior in which a revision-deletion form appears (CVE-2020-35477).

MediaWiki before 1.31.11 allows XSS via BlockLogFormatter.php.
Language::translateBlockExpiry itself does not escape in all code paths. For
example, the return of Language::userTimeAndDate is always unsafe for HTML
in a month value (CVE-2020-35479).

An issue was discovered in MediaWiki before 1.31.11. Missing users (accounts
that don't exist) and hidden users (accounts that have been explicitly hidden
due to being abusive, or similar) that the viewer cannot see are handled
differently, exposing sensitive information about the hidden status to
unprivileged viewers. This exists on various code paths (CVE-2020-35480).");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.31.12~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.31.12~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.31.12~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.31.12~1.mga7", rls:"MAGEIA7"))) {
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
