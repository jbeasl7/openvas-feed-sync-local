# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0155");
  script_cve_id("CVE-2023-3550", "CVE-2023-45359", "CVE-2023-45360", "CVE-2023-45361", "CVE-2023-45362", "CVE-2023-45363", "CVE-2023-45364", "CVE-2023-51704");
  script_tag(name:"creation_date", value:"2024-05-01 04:12:41 +0000 (Wed, 01 May 2024)");
  script_version("2024-05-02T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-05-02 05:05:31 +0000 (Thu, 02 May 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 16:00:30 +0000 (Thu, 12 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0155)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0155");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0155.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33156");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mediawiki' package(s) announced via the MGASA-2024-0155 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mediawiki v1.40.0 does not validate namespaces used in XML files.
Therefore, if the instance administrator allows XML file uploads, a
remote attacker with a low-privileged user account can use this exploit
to become an administrator by sending a malicious link to the instance
administrator. (CVE-2023-3550)
An issue was discovered in MediaWiki before 1.35.12, 1.36.x through
1.39.x before 1.39.5, and 1.40.x before 1.40.1. There is XSS in
youhavenewmessagesmanyusers and youhavenewmessages i18n messages. This
is related to MediaWiki:Youhavenewmessagesfromusers. (CVE-2023-45360)
An issue was discovered in DifferenceEngine.php in MediaWiki before
1.35.12, 1.36.x through 1.39.x before 1.39.5, and 1.40.x before 1.40.1.
diff-multi-sameuser (aka 'X intermediate revisions by the same user not
shown') ignores username suppression. This is an information leak.
(CVE-2023-45362)
An issue was discovered in ApiPageSet.php in MediaWiki before 1.35.12,
1.36.x through 1.39.x before 1.39.5, and 1.40.x before 1.40.1. It allows
attackers to cause a denial of service (unbounded loop and
RequestTimeoutException) when querying pages redirected to other
variants with redirects and converttitles set. (CVE-2023-45363)
An issue was discovered in includes/page/Article.php in MediaWiki 1.36.x
through 1.39.x before 1.39.5 and 1.40.x before 1.40.1. Deleted revision
existence is leaked due to incorrect permissions being checked. This
reveals that a given revision ID belonged to the given page title, and
its timestamp, both of which are not supposed to be public information.
(CVE-2023-45364)
An issue was discovered in MediaWiki before 1.35.14, 1.36.x through
1.39.x before 1.39.6, and 1.40.x before 1.40.2. In
includes/logging/RightsLogFormatter.php, group-*-member messages can
result in XSS on Special:log/rights. (CVE-2023-51704)");

  script_tag(name:"affected", value:"'mediawiki' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"mediawiki", rpm:"mediawiki~1.35.14~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-mysql", rpm:"mediawiki-mysql~1.35.14~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-pgsql", rpm:"mediawiki-pgsql~1.35.14~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mediawiki-sqlite", rpm:"mediawiki-sqlite~1.35.14~1.mga9", rls:"MAGEIA9"))) {
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
