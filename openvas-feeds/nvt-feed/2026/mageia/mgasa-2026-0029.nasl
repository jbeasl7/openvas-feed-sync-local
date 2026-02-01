# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0029");
  script_cve_id("CVE-2025-15467", "CVE-2025-68160", "CVE-2025-69418", "CVE-2025-69419", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22795", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-01-30 04:36:00 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2026-0029)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0029");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0029.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35077");
  script_xref(name:"URL", value:"https://openssl-library.org/news/secadv/20260127.txt");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/01/27/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/01/27/7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2026-0029 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stack buffer overflow in CMS AuthEnvelopedData parsing. (CVE-2025-15467)
Heap out-of-bounds write in BIO_f_linebuffer on short writes.
(CVE-2025-68160)
Unauthenticated/unencrypted trailing bytes with low-level OCB function
calls. (CVE-2025-69418)
Out of bounds write in PKCS12_get_friendlyname() UTF-8 conversion.
(CVE-2025-69419)
Missing ASN1_TYPE validation in TS_RESP_verify_response() function.
(CVE-2025-69420)
NULL Pointer Dereference in PKCS12_item_decrypt_d2i_ex function.
(CVE-2025-69421)
Missing ASN1_TYPE validation in PKCS#12 parsing. (CVE-2026-22795)
ASN1_TYPE Type Confusion in the PKCS7_digest_from_attributes() function.
(CVE-2026-22796)");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl3", rpm:"lib64openssl3~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~3.0.19~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~3.0.19~1.mga9", rls:"MAGEIA9"))) {
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
