# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1401.1");
  script_cve_id("CVE-2014-8146", "CVE-2014-8147", "CVE-2016-6293", "CVE-2017-14952", "CVE-2017-15422", "CVE-2017-17484", "CVE-2017-7867", "CVE-2017-7868");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-28 18:26:13 +0000 (Thu, 28 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1401-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1|SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1401-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181401-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990636");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/004085.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the SUSE-SU-2018:1401-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"icu was updated to fix two security issues.

These security issues were fixed:
- CVE-2014-8147: The resolveImplicitLevels function in common/ubidi.c
 in the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) used an integer data type
 that is inconsistent with a header file, which allowed remote attackers
 to cause a denial of service (incorrect malloc followed by invalid free)
 or possibly execute arbitrary code via crafted text (bsc#929629).
- CVE-2014-8146: The resolveImplicitLevels function in common/ubidi.c
 in the Unicode Bidirectional Algorithm implementation in ICU4C in
 International Components for Unicode (ICU) did not properly track
 directionally isolated pieces of text, which allowed remote attackers
 to cause a denial of service (heap-based buffer overflow) or possibly
 execute arbitrary code via crafted text (bsc#929629).
- CVE-2016-6293: The uloc_acceptLanguageFromHTTP function in
 common/uloc.cpp in International Components for Unicode (ICU) for C/C++
 did not ensure that there is a '\0' character at the end of a certain
 temporary array, which allowed remote attackers to cause a denial of
 service (out-of-bounds read) or possibly have unspecified other impact
 via a call with a long httpAcceptLanguage argument (bsc#990636).
- CVE-2017-7868: International Components for Unicode (ICU) for C/C++
 2017-02-13 has an out-of-bounds write caused by a heap-based buffer
 overflow related to the utf8TextAccess function in common/utext.cpp and
 the utext_moveIndex32* function (bsc#1034674)
- CVE-2017-7867: International Components for Unicode (ICU) for C/C++
 2017-02-13 has an out-of-bounds write caused by a heap-based buffer
 overflow related to the utf8TextAccess function in common/utext.cpp and
 the utext_setNativeIndex* function (bsc#1034678)
- CVE-2017-14952: Double free in i18n/zonemeta.cpp in International
 Components for Unicode (ICU) for C/C++ allowed remote attackers to
 execute arbitrary code via a crafted string, aka a 'redundant UVector
 entry clean up function call' issue (bnc#1067203)
- CVE-2017-17484: The ucnv_UTF8FromUTF8 function in ucnv_u8.cpp
 in International Components for Unicode (ICU) for C/C++ mishandled
 ucnv_convertEx calls for UTF-8 to UTF-8 conversion, which allowed remote
 attackers to cause a denial of service (stack-based buffer overflow
 and application crash) or possibly have unspecified other impact via a
 crafted string, as demonstrated by ZNC (bnc#1072193)
- CVE-2017-15422: An integer overflow in icu during persian calendar
 date processing could lead to incorrect years shown (bnc#1077999)");

  script_tag(name:"affected", value:"'icu' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.7.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.7.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.7.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libicu-doc", rpm:"libicu-doc~52.1~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-32bit", rpm:"libicu52_1-32bit~52.1~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1", rpm:"libicu52_1~52.1~8.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu52_1-data", rpm:"libicu52_1-data~52.1~8.7.1", rls:"SLES12.0SP3"))) {
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
