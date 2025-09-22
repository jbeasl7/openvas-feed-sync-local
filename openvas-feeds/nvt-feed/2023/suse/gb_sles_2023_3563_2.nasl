# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.3563.2");
  script_cve_id("CVE-2020-10531", "CVE-2020-21913");
  script_tag(name:"creation_date", value:"2023-10-24 04:21:12 +0000 (Tue, 24 Oct 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-18 16:40:03 +0000 (Wed, 18 Mar 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:3563-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3563-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233563-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/354372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/437293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824262");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-October/016813.html");
  script_xref(name:"URL", value:"https://unicode-org.atlassian.net/browse/ICU-21361");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu73_2' package(s) announced via the SUSE-SU-2023:3563-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for icu73_2 fixes the following issues:

- Update to release 73.2

 * CLDR extends the support for 'short' Chinese sort orders to
 cover some additional, required characters for Level 2. This
 is carried over into ICU collation.
 * ICU has a modified character conversion table, mapping some
 GB18030 characters to Unicode characters that were encoded
 after GB18030-2005.

- fixes builds where UCHAR_TYPE is re-defined such as libqt5-qtwebengine

- Update to release 73.1

 * Improved Japanese and Korean short-text line breaking
 * Reduction of C++ memory use in date formatting

- Update to release 72.1

 * Support for Unicode 15, including new characters, scripts,
 emoji, and corresponding API constants.
 * Support for CLDR 42 locale data with various additions and
 corrections.
 * Shift to tzdb 2022e. Pre-1970 data for a number of timezones
 has been removed.

- bump library packagename to libicu71 to match the version.

- update to 71.1:

 * updates to CLDR 41 locale data with various additions and corrections.
 * phrase-based line breaking for Japanese. Existing line breaking methods
 follow standards and conventions for body text but do not work well for
 short Japanese text, such as in titles and headings. This new feature is
 optimized for these use cases.
 * support for Hindi written in Latin letters (hi_Latn). The CLDR data for
 this increasingly popular locale has been significantly revised and
 expanded. Note that based on user expectations, hi_Latn incorporates a
 large amount of English, and can also be referred to as 'Hinglish'.
 * time zone data updated to version 2022a. Note that pre-1970 data for a
 number of time zones has been removed, as has been the case in the upstream
 tzdata release since 2021b.

- ICU-21793 Fix ucptrietest golden diff [bsc#1192935]

- Update to release 70.1:

 * Unicode 14 (new characters, scripts, emoji, and API constants)
 * CLDR 40 (many additions and corrections)
 * Fixes for measurement unit formatting
 * Can now be built with up to C++20 compilers

- ICU-21613 Fix undefined behaviour in ComplexUnitsConverter::applyRounder

- Update to release 69.1

 * CLDR 39
 * For Norwegian, 'no' is back to being the canonical code, with
 'nb' treated as equivalent. This aligns handling of Norwegian
 with other macro language codes.
 * Binary prefixes in measurement units (KiB, MiB, etc.)
 * Time zone offsets from local time: New APIs
 BasicTimeZone::getOffsetFromLocal() (C++) and
 ucal_getTimeZoneOffsetFromLocal()

- Backport ICU-21366 (bsc#1182645)

- Update to release 68.2

 * Fix memory problem in FormattedStringBuilder
 * Fix assertion when setKeywordValue w/ long value.
 * Fix UBSan breakage on 8bit of rbbi
 * fix int32_t overflow in listFormat
 * Fix memory handling in MemoryPool::operator=()
 * Fix memory leak in AliasReplacer

- Add back icu.keyring, see [link moved to references]

- Update to release 68.1

 * CLDR 38
 * ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'icu73_2' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2", rpm:"libicu73_2~73.2~150000.1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-bedata", rpm:"libicu73_2-bedata~73.2~150000.1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-devel", rpm:"libicu73_2-devel~73.2~150000.1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-doc", rpm:"libicu73_2-doc~73.2~150000.1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-ledata", rpm:"libicu73_2-ledata~73.2~150000.1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2", rpm:"libicu73_2~73.2~150000.1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-bedata", rpm:"libicu73_2-bedata~73.2~150000.1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-devel", rpm:"libicu73_2-devel~73.2~150000.1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-doc", rpm:"libicu73_2-doc~73.2~150000.1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-ledata", rpm:"libicu73_2-ledata~73.2~150000.1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2", rpm:"libicu73_2~73.2~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-bedata", rpm:"libicu73_2-bedata~73.2~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-devel", rpm:"libicu73_2-devel~73.2~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-doc", rpm:"libicu73_2-doc~73.2~150000.1.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libicu73_2-ledata", rpm:"libicu73_2-ledata~73.2~150000.1.3.1", rls:"SLES15.0SP3"))) {
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
