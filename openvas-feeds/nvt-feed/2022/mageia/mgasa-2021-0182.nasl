# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0182");
  script_cve_id("CVE-2020-1946");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-27 01:28:53 +0000 (Sat, 27 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0182");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0182.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28673");
  script_xref(name:"URL", value:"https://spamassassin.apache.org/news.html");
  script_xref(name:"URL", value:"https://svn.apache.org/repos/asf/spamassassin/branches/3.4/build/announcements/3.4.5.txt");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/03/24/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spamassassin, spamassassin-rules' package(s) announced via the MGASA-2021-0182 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Apache SpamAssassin before 3.4.5, malicious rule configuration (.cf) files
can be configured to run system commands without any output or errors. With
this, exploits can be injected in a number of scenarios. In addition to upgrading
to SA version 3.4.5, users should only use update channels or 3rd party .cf
files from trusted places. (CVE-2020-1946)");

  script_tag(name:"affected", value:"'spamassassin, spamassassin-rules' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin-Spamd", rpm:"perl-Mail-SpamAssassin-Spamd~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-rules", rpm:"spamassassin-rules~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-sa-compile", rpm:"spamassassin-sa-compile~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamc", rpm:"spamassassin-spamc~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamd", rpm:"spamassassin-spamd~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-tools", rpm:"spamassassin-tools~3.4.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin", rpm:"perl-Mail-SpamAssassin~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Mail-SpamAssassin-Spamd", rpm:"perl-Mail-SpamAssassin-Spamd~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin", rpm:"spamassassin~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-rules", rpm:"spamassassin-rules~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-sa-compile", rpm:"spamassassin-sa-compile~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamc", rpm:"spamassassin-spamc~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-spamd", rpm:"spamassassin-spamd~3.4.5~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spamassassin-tools", rpm:"spamassassin-tools~3.4.5~1.mga8", rls:"MAGEIA8"))) {
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
