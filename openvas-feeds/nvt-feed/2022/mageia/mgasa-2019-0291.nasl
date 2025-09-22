# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0291");
  script_cve_id("CVE-2019-9511", "CVE-2019-9513");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-23 13:44:08 +0000 (Fri, 23 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0291)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0291");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0291.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:2692");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25424");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2' package(s) announced via the MGASA-2019-0291 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

Some HTTP/2 implementations are vulnerable to window size manipulation
and stream prioritization manipulation, potentially leading to a denial
of service. The attacker requests a large amount of data from a specified
resource over multiple streams. They manipulate window size and stream
priority to force the server to queue the data in 1-byte chunks. Depending
on how efficiently this data is queued, this can consume excess CPU,
memory, or both. (CVE-2019-9511)

Some HTTP/2 implementations are vulnerable to resource loops, potentially
leading to a denial of service. The attacker creates multiple request
streams and continually shuffles the priority of the streams in a way that
causes substantial churn to the priority tree. This can consume excess CPU.
(CVE-2019-9513)");

  script_tag(name:"affected", value:"'nghttp2' package(s) on Mageia 6, Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2-devel", rpm:"lib64nghttp2-devel~1.9.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2_14", rpm:"lib64nghttp2_14~1.9.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.9.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_14", rpm:"libnghttp2_14~1.9.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.9.2~1.1.mga6", rls:"MAGEIA6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2-devel", rpm:"lib64nghttp2-devel~1.38.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nghttp2_14", rpm:"lib64nghttp2_14~1.38.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2-devel", rpm:"libnghttp2-devel~1.38.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnghttp2_14", rpm:"libnghttp2_14~1.38.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nghttp2", rpm:"nghttp2~1.38.0~1.1.mga7", rls:"MAGEIA7"))) {
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
