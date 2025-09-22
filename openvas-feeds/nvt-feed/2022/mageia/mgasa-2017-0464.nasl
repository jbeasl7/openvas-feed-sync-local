# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0464");
  script_cve_id("CVE-2017-12132", "CVE-2017-12133", "CVE-2017-15670", "CVE-2017-15671", "CVE-2017-15804");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-24 14:34:48 +0000 (Tue, 24 Oct 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0464)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0464");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0464.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21582");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc, libtirpc' package(s) announced via the MGASA-2017-0464 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The DNS stub resolver in the GNU C Library (aka glibc or libc6) before
version 2.26, when EDNS support is enabled, will solicit large UDP
responses from name servers, potentially simplifying off-path DNS
spoofing attacks due to IP fragmentation.(CVE-2017-12132, CVE-2017-12133).

The GNU C Library (aka glibc or libc6) before 2.27 contains an off-by-one
error leading to a heap-based buffer overflow (CVE-2017-15670).

The glob function in glob.c in the GNU C Library (aka glibc or libc6)
before 2.27, when invoked with GLOB_TILDE, could skip freeing allocated
memory when processing the ~ operator with a long user name, potentially
leading to a denial of service (memory leak) (CVE-2017-15671).

The glob function in glob.c in the GNU C Library (aka glibc or libc6)
before 2.27 contains a buffer overflow during unescaping of user names
with the ~ operator (CVE-2017-15804).

As libtirpc is also affected by CVE-2017-12133, it's part of this update.");

  script_tag(name:"affected", value:"'glibc, libtirpc' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.22~26.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tirpc-devel", rpm:"lib64tirpc-devel~1.0.1~5.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tirpc3", rpm:"lib64tirpc3~1.0.1~5.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc", rpm:"libtirpc~1.0.1~5.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-devel", rpm:"libtirpc-devel~1.0.1~5.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3", rpm:"libtirpc3~1.0.1~5.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.22~26.mga6", rls:"MAGEIA6"))) {
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
