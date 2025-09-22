# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120745");
  script_cve_id("CVE-2016-6662");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:28 +0000 (Wed, 26 Oct 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 17:41:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-756)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-756");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-756.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql55, mysql56' package(s) announced via the ALAS-2016-756 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the MySQL logging functionality allowed writing to MySQL configuration files. An administrative database user, or a database user with FILE privileges, could possibly use this flaw to run arbitrary commands with root privileges on the system running the database server.");

  script_tag(name:"affected", value:"'mysql55, mysql56' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mysql-config", rpm:"mysql-config~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55", rpm:"mysql55~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-bench", rpm:"mysql55-bench~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-debuginfo", rpm:"mysql55-debuginfo~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-devel", rpm:"mysql55-devel~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded", rpm:"mysql55-embedded~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-embedded-devel", rpm:"mysql55-embedded-devel~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-libs", rpm:"mysql55-libs~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-server", rpm:"mysql55-server~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql55-test", rpm:"mysql55-test~5.5.52~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56", rpm:"mysql56~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-bench", rpm:"mysql56-bench~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-common", rpm:"mysql56-common~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-debuginfo", rpm:"mysql56-debuginfo~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-devel", rpm:"mysql56-devel~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-embedded", rpm:"mysql56-embedded~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-embedded-devel", rpm:"mysql56-embedded-devel~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-errmsg", rpm:"mysql56-errmsg~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-libs", rpm:"mysql56-libs~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-server", rpm:"mysql56-server~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql56-test", rpm:"mysql56-test~5.6.33~1.21.amzn1", rls:"AMAZON"))) {
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
