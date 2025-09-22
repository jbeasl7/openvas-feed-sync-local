# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1555.1");
  script_cve_id("CVE-2024-45336", "CVE-2024-45341", "CVE-2025-22866");
  script_tag(name:"creation_date", value:"2025-05-22 12:07:17 +0000 (Thu, 22 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1555-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251555-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236801");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039220.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.22-openssl' package(s) announced via the SUSE-SU-2025:1555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2024-45336: net/http: sensitive headers incorrectly sent after cross-domain redirect (bsc#1236046)
- CVE-2024-45341: crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints (bsc#1236045)
- CVE-2025-22866: crypto/internal/fips140/nistec: p256NegCond is variable time on ppc64le (bsc#1236801)");

  script_tag(name:"affected", value:"'go1.22-openssl' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl", rpm:"go1.22-openssl~1.22.12~150000.1.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-doc", rpm:"go1.22-openssl-doc~1.22.12~150000.1.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-race", rpm:"go1.22-openssl-race~1.22.12~150000.1.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl", rpm:"go1.22-openssl~1.22.12~150000.1.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-doc", rpm:"go1.22-openssl-doc~1.22.12~150000.1.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-race", rpm:"go1.22-openssl-race~1.22.12~150000.1.12.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl", rpm:"go1.22-openssl~1.22.12~150000.1.12.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-doc", rpm:"go1.22-openssl-doc~1.22.12~150000.1.12.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-openssl-race", rpm:"go1.22-openssl-race~1.22.12~150000.1.12.1", rls:"SLES15.0SP5"))) {
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
