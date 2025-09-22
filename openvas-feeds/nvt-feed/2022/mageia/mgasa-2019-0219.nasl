# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0219");
  script_cve_id("CVE-2019-11356");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 16:34:32 +0000 (Tue, 04 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0219)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0219");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0219.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:1771");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25134");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd' package(s) announced via the MGASA-2019-0219 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cyrus-imapd package fixes security vulnerability:

It was discovered that cyrus-imapd had a buffer overflow in CalDAV request
handling triggered by a long iCalendar property name (CVE-2019-11356).");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on Mageia 6, Mageia 7.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd-devel", rpm:"lib64cyrus-imapd-devel~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd0", rpm:"lib64cyrus-imapd0~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd-devel", rpm:"libcyrus-imapd-devel~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd0", rpm:"libcyrus-imapd0~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.5.11~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd-devel", rpm:"lib64cyrus-imapd-devel~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cyrus-imapd0", rpm:"lib64cyrus-imapd0~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd-devel", rpm:"libcyrus-imapd-devel~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcyrus-imapd0", rpm:"libcyrus-imapd0~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~2.5.11~7.1.mga7", rls:"MAGEIA7"))) {
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
