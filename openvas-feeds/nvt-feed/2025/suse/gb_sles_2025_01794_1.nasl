# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01794.1");
  script_cve_id("CVE-2025-32906", "CVE-2025-32909", "CVE-2025-32910", "CVE-2025-32911", "CVE-2025-32912", "CVE-2025-32913", "CVE-2025-4948", "CVE-2025-4969");
  script_tag(name:"creation_date", value:"2025-06-04 04:11:09 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01794-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01794-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501794-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243423");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/039487.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the SUSE-SU-2025:01794-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup fixes the following issues:

- CVE-2025-4948: Fixed integer underflow in soup_multipart_new_from_message() leading to denial of service (bsc#1243332)
- CVE-2025-4969: Fixed off-by-one out-of-bounds read may lead to infoleak (bsc#1243423)
- CVE-2025-32906: Fixed out of bounds reads in soup_headers_parse_request() (bsc#1241263)
- CVE-2025-32909: Fixed NULL pointer dereference in the sniff_mp4 function in soup-content-sniffer.c (bsc#1241226)
- CVE-2025-32910: Fixed null pointer deference on client when server omits the realm parameter in an Unauthorized response with Digest authentication (bsc#1241252)
- CVE-2025-32911: Fixed double free on soup_message_headers_get_content_disposition() via 'params'. (bsc#1241238)
- CVE-2025-32912: Fixed NULL pointer dereference in SoupAuthDigest (bsc#1241214)
- CVE-2025-32913: Fixed NULL pointer dereference in soup_message_headers_get_content_disposition (bsc#1241162)");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1", rpm:"libsoup-2_4-1~2.62.2~5.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-2_4-1-32bit", rpm:"libsoup-2_4-1-32bit~2.62.2~5.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~2.62.2~5.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~2.62.2~5.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-2_4", rpm:"typelib-1_0-Soup-2_4~2.62.2~5.15.1", rls:"SLES12.0SP5"))) {
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
