# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1518.1");
  script_cve_id("CVE-2024-52530", "CVE-2024-52531", "CVE-2024-52532", "CVE-2025-2784", "CVE-2025-32050", "CVE-2025-32052", "CVE-2025-32053", "CVE-2025-32907", "CVE-2025-32914", "CVE-2025-46420", "CVE-2025-46421");
  script_tag(name:"creation_date", value:"2025-05-12 04:09:48 +0000 (Mon, 12 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-14 15:15:25 +0000 (Mon, 14 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1518-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1518-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251518-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241688");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039181.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the SUSE-SU-2025:1518-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup fixes the following issues:

 - CVE-2024-52530: Fixed HTTP request smuggling via stripping null bytes from the ends of header names (bsc#1233285)
 - CVE-2024-52531: Fixed buffer overflow via UTF-8 conversion in soup_header_parse_param_list_strict (bsc#1233292)
 - CVE-2024-52532: Fixed infinite loop while reading websocket data (bsc#1233287)
 - CVE-2025-2784: Fixed heap buffer over-read in `skip_insignificant_space` when sniffing content (bsc#1240750)
 - CVE-2025-32050: Fixed integer overflow in append_param_quoted (bsc#1240752)
 - CVE-2025-32052: Fixed heap buffer overflow in sniff_unknown() (bsc#1240756)
 - CVE-2025-32053: Fixed heap buffer overflows in sniff_feed_or_html() and skip_insignificant_space() (bsc#1240757)
 - CVE-2025-32907: Fixed excessive memory consumption in server when client requests a large amount of overlapping ranges in a single HTTP request (bsc#1241222)
 - CVE-2025-32914: Fixed out of bounds read in `soup_multipart_new_from_message()` (bsc#1241164)
 - CVE-2025-46420: Fixed memory leak on soup_header_parse_quality_list() via soup-headers.c (bsc#1241686)
 - CVE-2025-46421: Fixed HTTP Authorization Header leak via an HTTP redirect (bsc#1241688)");

  script_tag(name:"affected", value:"'libsoup' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.62.2~5.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-32bit", rpm:"libsoup-2_4-1-32bit~2.62.2~5.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.62.2~5.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~2.62.2~5.12.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.62.2~5.12.1", rls:"SLES12.0SP5"))) {
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
