# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02120.1");
  script_cve_id("CVE-2025-0913", "CVE-2025-22874", "CVE-2025-4673");
  script_tag(name:"creation_date", value:"2025-06-30 04:16:24 +0000 (Mon, 30 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02120-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02120-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502120-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244158");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040493.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.24-openssl' package(s) announced via the SUSE-SU-2025:02120-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.24-openssl fixes the following issues:

Update to version 1.24.4 (bsc#1236217):

- CVE-2025-22874 crypto/x509: ExtKeyUsageAny bypasses policy validation (bsc#1244158).
- CVE-2025-0913 os: inconsistent handling of O_CREATE<pipe>O_EXCL on Unix and Windows (bsc#1244157).
- CVE-2025-4673 net/http: sensitive headers not cleared on cross-origin redirect (bsc#1244156).");

  script_tag(name:"affected", value:"'go1.24-openssl' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl", rpm:"go1.24-openssl~1.24.4~150000.1.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-doc", rpm:"go1.24-openssl-doc~1.24.4~150000.1.9.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-race", rpm:"go1.24-openssl-race~1.24.4~150000.1.9.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl", rpm:"go1.24-openssl~1.24.4~150000.1.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-doc", rpm:"go1.24-openssl-doc~1.24.4~150000.1.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-race", rpm:"go1.24-openssl-race~1.24.4~150000.1.9.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl", rpm:"go1.24-openssl~1.24.4~150000.1.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-doc", rpm:"go1.24-openssl-doc~1.24.4~150000.1.9.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-openssl-race", rpm:"go1.24-openssl-race~1.24.4~150000.1.9.1", rls:"SLES15.0SP5"))) {
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
