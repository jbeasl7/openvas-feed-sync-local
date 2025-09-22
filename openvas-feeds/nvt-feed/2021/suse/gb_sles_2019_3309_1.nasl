# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3309.1");
  script_cve_id("CVE-2019-18422", "CVE-2019-18423", "CVE-2019-19577", "CVE-2019-19578", "CVE-2019-19579", "CVE-2019-19580", "CVE-2019-19581", "CVE-2019-19582", "CVE-2019-19583");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-19 18:51:41 +0000 (Thu, 19 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3309-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193309-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2019:3309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:
CVE-2019-19581: Fixed a potential out of bounds on 32-bit Arm
 (bsc#1158003 XSA-307).

CVE-2019-19582: Fixed a potential infinite loop when x86 accesses to
 bitmaps with a compile time known size of 64 (bsc#1158003 XSA-307).

CVE-2019-19583: Fixed improper checks which could have allowed HVM/PVH
 guest userspace code to crash the guest,leading to a guest denial of
 service (bsc#1158004 XSA-308).

CVE-2019-19578: Fixed an issue where a malicious or buggy PV guest could
 have caused hypervisor crash resulting in denial of service affecting
 the entire host (bsc#1158005 XSA-309).

CVE-2019-19580: Fixed a privilege escalation where a malicious PV guest
 administrator could have been able to escalate their privilege to that
 of the host (bsc#1158006 XSA-310).

CVE-2019-19577: Fixed an issue where a malicious guest administrator
 could have caused Xen to access data structures while they are being
 modified leading to a crash (bsc#1158007 XSA-311).

CVE-2019-19579: Fixed a privilege escalation where an untrusted domain
 with access to a physical device can DMA into host memory (bsc#1157888
 XSA-306).

CVE-2019-18423: A malicious guest administrator may cause a hypervisor
 crash, resulting in a Denial of Service (DoS) (bsc#1154460 XSA-301).

CVE-2019-18422: A malicious ARM guest might contrive to arrange for
 critical Xen code to run with interrupts erroneously enabled. This could
 lead to data corruption, denial of service, or possibly even privilege
 escalation. However a precise attack technique has not been identified.
 (bsc#1154464 XSA-303)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.10.4_08~3.28.1", rls:"SLES15.0"))) {
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
