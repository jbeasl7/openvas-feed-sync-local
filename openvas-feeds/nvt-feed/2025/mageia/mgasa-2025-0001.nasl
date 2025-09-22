# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0001");
  script_cve_id("CVE-2024-35176", "CVE-2024-39908", "CVE-2024-41123", "CVE-2024-41946", "CVE-2024-43398", "CVE-2024-49761");
  script_tag(name:"creation_date", value:"2025-01-06 11:56:29 +0000 (Mon, 06 Jan 2025)");
  script_version("2025-01-07T06:11:07+0000");
  script_tag(name:"last_modification", value:"2025-01-07 06:11:07 +0000 (Tue, 07 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:41:46 +0000 (Tue, 05 Nov 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0001.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33576");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/RQWXWS2GDTKX4LYWHQOZ2PWXDEICDX2W/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7091-1");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/05/16/dos-rexml-cve-2024-35176/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/07/16/dos-rexml-cve-2024-39908/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/08/01/dos-rexml-cve-2024-41123/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/08/01/dos-rexml-cve-2024-41946/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/08/22/dos-rexml-cve-2024-43398/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2024/10/28/redos-rexml-cve-2024-49761/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2025-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The REXML gem before 3.2.6 has a denial of service vulnerability when it
parses an XML that has many `<`s in an attribute value. (CVE-2024-35176)
The REXML gem before 3.3.1 has some DoS vulnerabilities when it parses
an XML that has many specific characters such as `<`, `0` and `%>`.
(CVE-2024-39908)
The REXML gem before 3.3.2 has some DoS vulnerabilities when it parses
an XML that has many specific characters such as whitespace character,
`>]` and `]>`. (CVE-2024-41123)
The REXML gem 3.3.2 has a DoS vulnerability when it parses an XML that
has many entity expansions with SAX2 or pull parser API.
(CVE-2024-41946)
The REXML gem before 3.3.6 has a DoS vulnerability when it parses an XML
that has many deep elements that have same local name attributes.
(CVE-2024-43398)
The REXML gem before 3.3.9 has a ReDoS vulnerability when it parses an
XML that has many digits between &# and x..., in a hex numeric character
reference (&#x...,). (CVE-2024-49761)");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby3.1", rpm:"lib64ruby3.1~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby3.1", rpm:"libruby3.1~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-RubyGems", rpm:"ruby-RubyGems~3.3.26~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bigdecimal", rpm:"ruby-bigdecimal~3.1.1~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundled-gems", rpm:"ruby-bundled-gems~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-bundler", rpm:"ruby-bundler~2.3.27~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.5.11~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~3.1.5~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-json", rpm:"ruby-json~2.6.1~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~2.0.1~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-psych", rpm:"ruby-psych~4.0.4~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rake", rpm:"ruby-rake~13.0.6~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rbs", rpm:"ruby-rbs~2.7.0~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~6.4.1.1~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rexml", rpm:"ruby-rexml~3.3.9~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rss", rpm:"ruby-rss~0.2.9~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.5.3~46.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-typeprof", rpm:"ruby-typeprof~0.21.3~46.mga9", rls:"MAGEIA9"))) {
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
