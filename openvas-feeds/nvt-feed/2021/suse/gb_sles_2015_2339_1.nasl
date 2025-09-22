# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2339.1");
  script_cve_id("CVE-2015-0272", "CVE-2015-5157", "CVE-2015-5307", "CVE-2015-6937", "CVE-2015-7509", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-12-28 19:44:20 +0000 (Mon, 28 Dec 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2339-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152339-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/932805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/942938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/943786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/946309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/949981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/953980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956709");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-December/001755.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:2339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

Following security bugs were fixed:
- CVE-2015-7509: Mounting ext4 filesystems in no-journal mode could hav lead to a system crash (bsc#956709).
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the Linux kernel did not ensure that certain slot numbers are valid, which allowed local users to cause a denial of service (NULL pointer dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call (bnc#949936).
- CVE-2015-8104: The KVM subsystem in the Linux kernel allowed guest OS users to cause a denial of service (host OS panic or hang) by triggering many #DB (aka Debug) exceptions, related to svm.c (bnc#954404).
- CVE-2015-5307: The KVM subsystem in the Linux kernel allowed guest OS users to cause a denial of service (host OS panic or hang) by triggering many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c (bnc#953527).
- CVE-2015-7990: RDS: There was no verification that an underlying transport exists when creating a connection, causing usage of a NULL pointer (bsc#952384).
- CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux kernel on the x86_64 platform mishandled IRET faults in processing NMIs that occurred during userspace execution, which might have allowed local users to gain privileges by triggering an NMI (bnc#938706).
- CVE-2015-7872: The key_gc_unused_keys function in security/keys/gc.c in the Linux kernel allowed local users to cause a denial of service (OOPS) via crafted keyctl commands (bnc#951440).
- CVE-2015-0272: Missing checks allowed remote attackers to cause a denial of service (IPv6 traffic disruption) via a crafted MTU value in an IPv6 Router Advertisement (RA) message, a different vulnerability than CVE-2015-8215 (bnc#944296).
- CVE-2015-6937: The __rds_conn_create function in net/rds/connection.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by using a socket that was not properly bound (bnc#945825).

The following non-security bugs were fixed:
- ALSA: hda - Disable 64bit address for Creative HDA controllers (bnc#814440).
- Driver: Vmxnet3: Fix ethtool -S to return correct rx queue stats (bsc#950750).
- Drivers: hv: do not do hypercalls when hypercall_page is NULL.
- Drivers: hv: kvp: move poll_channel() to hyperv_vmbus.h.
- Drivers: hv: util: move kvp/vss function declarations to hyperv_vmbus.h.
- Drivers: hv: vmbus: Get rid of some unused definitions.
- Drivers: hv: vmbus: Implement the protocol for tearing down vmbus state.
- Drivers: hv: vmbus: add special crash handler (bnc#930770).
- Drivers: hv: vmbus: add special kexec handler.
- Drivers: hv: vmbus: kill tasklets on module unload.
- Drivers: hv: vmbus: prefer '^A' notification chain to 'panic'.
- Drivers: hv: vmbus: remove hv_synic_free_cpu() ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~68.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~68.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~68.1", rls:"SLES11.0SP4"))) {
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
