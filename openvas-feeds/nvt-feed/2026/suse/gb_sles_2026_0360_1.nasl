# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0360.1");
  script_cve_id("CVE-2025-68160", "CVE-2025-69418", "CVE-2025-69419", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22795", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-02-04 07:44:24 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-02 18:29:59 +0000 (Mon, 02 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260360-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256840");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024012.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_1' package(s) announced via the SUSE-SU-2026:0360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 fixes the following issues:

- CVE-2026-22795: Missing ASN1_TYPE validation in PKCS#12 parsing (bsc#1256839).
- CVE-2025-69420: Missing ASN1_TYPE validation in TS_RESP_verify_response() function (bsc#1256837).
- CVE-2025-69421: NULL Pointer Dereference in PKCS12_item_decrypt_d2i_ex function (bsc#1256838).
- CVE-2026-22796: ASN1_TYPE Type Confusion in the PKCS7_digest_from_attributes() function (bsc#1256840).
- CVE-2025-68160: Heap out-of-bounds write in BIO_f_linebuffer on short writes (bsc#1256834).
- CVE-2025-69418: Unauthenticated/unencrypted trailing bytes with low-level OCB function calls (bsc#1256835).
- CVE-2025-69419: Out of bounds write in PKCS12_get_friendlyname() UTF-8 conversion (bsc#1256836).");

  script_tag(name:"affected", value:"'openssl-1_1' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-32bit", rpm:"libopenssl-1_1-devel-32bit~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.1l~150400.7.87.1", rls:"SLES15.0SP4"))) {
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
