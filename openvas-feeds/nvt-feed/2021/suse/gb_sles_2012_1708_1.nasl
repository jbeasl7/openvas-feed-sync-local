# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1708.1");
  script_cve_id("CVE-2011-0695", "CVE-2012-3430");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1708-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1708-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121708-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ofed' package(s) announced via the SUSE-SU-2012:1708-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of ofed fixed multiple issues (including security related flaws):

 * sdp: move histogram allocation from stack to heap
(bnc#706175)
 * cma: Fix crash in request handlers (bnc#678795,
CVE-2011-0695)
 * rds: set correct msg_namelen (bnc#773383,
CVE-2012-3430)
 * cm: Bump reference count on cm_id before invoking
(bnc#678795, CVE-2011-0695)
 * sdp / ipath: Added fixes for 64bit divide on 32bit builds
 * updated Infiniband sysconfig file to match openibd
(bnc#721597)

Security Issue reference:

 * CVE-2012-3430
>");

  script_tag(name:"affected", value:"'ofed' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ofed", rpm:"ofed~1.5.2~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-bigsmp", rpm:"ofed-cxgb3-NIC-kmp-bigsmp~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-debug", rpm:"ofed-cxgb3-NIC-kmp-debug~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-default", rpm:"ofed-cxgb3-NIC-kmp-default~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-kdump", rpm:"ofed-cxgb3-NIC-kmp-kdump~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-kdumppae", rpm:"ofed-cxgb3-NIC-kmp-kdumppae~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-ppc64", rpm:"ofed-cxgb3-NIC-kmp-ppc64~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-smp", rpm:"ofed-cxgb3-NIC-kmp-smp~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-vmi", rpm:"ofed-cxgb3-NIC-kmp-vmi~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-cxgb3-NIC-kmp-vmipae", rpm:"ofed-cxgb3-NIC-kmp-vmipae~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-doc", rpm:"ofed-doc~1.5.2~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-bigsmp", rpm:"ofed-kmp-bigsmp~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-debug", rpm:"ofed-kmp-debug~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-default", rpm:"ofed-kmp-default~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-kdump", rpm:"ofed-kmp-kdump~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-kdumppae", rpm:"ofed-kmp-kdumppae~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-ppc64", rpm:"ofed-kmp-ppc64~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-smp", rpm:"ofed-kmp-smp~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-vmi", rpm:"ofed-kmp-vmi~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofed-kmp-vmipae", rpm:"ofed-kmp-vmipae~1.5.2_2.6.16.60_0.99.13~0.12.1", rls:"SLES10.0SP4"))) {
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
