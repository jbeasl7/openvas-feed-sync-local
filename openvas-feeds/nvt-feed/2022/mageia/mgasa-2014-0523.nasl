# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0523");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0523)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0523");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0523.html");
  script_xref(name:"URL", value:"http://tracker.firebirdsql.org/browse/CORE-4630");
  script_xref(name:"URL", value:"http://www.firebirdsql.org/en/news/security-updates-for-v2-1-and-v2-5-series-66011/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14726");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firebird' package(s) announced via the MGASA-2014-0523 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"These update fix the recently discovered security vulnerability (CORE-4630)
that may be used for a remote DoS attack performed by unauthorized users");

  script_tag(name:"affected", value:"'firebird' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"firebird", rpm:"firebird~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-classic", rpm:"firebird-classic~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-devel", rpm:"firebird-devel~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-server-classic", rpm:"firebird-server-classic~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-server-common", rpm:"firebird-server-common~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-server-superserver", rpm:"firebird-server-superserver~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-superclassic", rpm:"firebird-superclassic~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-superserver", rpm:"firebird-superserver~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-utils-classic", rpm:"firebird-utils-classic~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-utils-common", rpm:"firebird-utils-common~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firebird-utils-superserver", rpm:"firebird-utils-superserver~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fbclient2", rpm:"lib64fbclient2~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64fbembed2", rpm:"lib64fbembed2~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbclient2", rpm:"libfbclient2~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfbembed2", rpm:"libfbembed2~2.5.2.26540~4.mga4", rls:"MAGEIA4"))) {
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
