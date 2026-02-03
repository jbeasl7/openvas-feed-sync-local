# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0332.1");
  script_cve_id("CVE-2025-68160", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-02-02 04:42:36 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0332-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260332-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256840");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023983.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_0_0' package(s) announced via the SUSE-SU-2026:0332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_0_0 fixes the following issues:

- CVE-2025-68160: Heap out-of-bounds write in BIO_f_linebuffer on short writes (bsc#1256834).
- CVE-2025-69420: Missing ASN1_TYPE validation in TS_RESP_verify_response() function (bsc#1256837).
- CVE-2025-69421: NULL Pointer Dereference in PKCS12_item_decrypt_d2i_ex function (bsc#1256838).
- CVE-2026-22796: ASN1_TYPE Type Confusion in the PKCS7_digest_from_attributes() function (bsc#1256840).");

  script_tag(name:"affected", value:"'openssl-1_0_0' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel-32bit", rpm:"libopenssl-1_0_0-devel-32bit~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam", rpm:"libopenssl1_0_0-steam~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit", rpm:"libopenssl1_0_0-steam-32bit~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-cavs", rpm:"openssl-1_0_0-cavs~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-doc", rpm:"openssl-1_0_0-doc~1.0.2p~150000.3.102.1", rls:"openSUSELeap15.6"))) {
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
