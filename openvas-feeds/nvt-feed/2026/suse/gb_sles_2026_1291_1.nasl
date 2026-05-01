# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1291.1");
  script_cve_id("CVE-2026-28387", "CVE-2026-28388", "CVE-2026-28389", "CVE-2026-31789", "CVE-2026-31790");
  script_tag(name:"creation_date", value:"2026-04-15 04:59:08 +0000 (Wed, 15 Apr 2026)");
  script_version("2026-04-15T06:17:01+0000");
  script_tag(name:"last_modification", value:"2026-04-15 06:17:01 +0000 (Wed, 15 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1291-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1291-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261291-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1260445");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-April/025311.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_0_0' package(s) announced via the SUSE-SU-2026:1291-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_0_0 fixes the following issues:

- CVE-2026-28387: Potential use-after-free in DANE client code (bsc#1260441).
- CVE-2026-28388: NULL Pointer Dereference When Processing a Delta CRL (bsc#1260442).
- CVE-2026-28389: Possible NULL dereference when processing CMS KeyAgreeRecipientInfo (bsc#1260443).
- CVE-2026-31789: Heap buffer overflow in hexadecimal conversion (bsc#1260444).
- CVE-2026-31790: Incorrect failure handling in RSA KEM RSASVE encapsulation (bsc#1260445).");

  script_tag(name:"affected", value:"'openssl-1_0_0' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~150000.3.105.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~150000.3.105.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~150000.3.105.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~150000.3.105.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~150000.3.105.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~150000.3.105.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~150000.3.105.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~150000.3.105.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~150000.3.105.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~150000.3.105.1", rls:"SLES15.0SP6"))) {
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
