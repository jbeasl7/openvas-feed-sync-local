# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1749.1");
  script_cve_id("CVE-2013-2206");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1749-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1749-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131749-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2013:1749-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to version 3.0.101 and also includes various other bug and security fixes. The following features have been added: * Drivers: hv: Support handling multiple VMBUS versions (FATE#314665). * Drivers: hv: Save and export negotiated vmbus version (FATE#314665). * Drivers: hv: Move vmbus version definitions to hyperv.h (FATE#314665). The following security issue has been fixed: * CVE-2013-2206: The sctp_sf_do_5_2_4_dupcook function in net/sctp/sm_statefuns.c in the SCTP implementation in the Linux kernel did not properly handle associations during the processing of a duplicate COOKIE ECHO chunk, which allowed remote attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via crafted SCTP traffic. (bnc#826102) The following non-security bugs have been fixed: * mm, memcg: introduce own oom handler to iterate only over its own threads. * mm, memcg: move all oom handling to memcontrol.c. * mm, oom: avoid looping when chosen thread detaches its mm. * mm, oom: fold oom_kill_task() into oom_kill_process(). * mm, oom: introduce helper function to process threads during scan. * mm, oom: reduce dependency on tasklist_lock (Reduce tasklist_lock hold times) (bnc#821259). * mm: do not walk all of system memory during show_mem (Reduce tasklist_lock hold times) (bnc#821259). * iommu/vt-d: add quirk for broken interrupt remapping on 55XX chipsets (bnc#844513). * x86/iommu/vt-d: Expand interrupt remapping quirk to cover x58 chipset (bnc#844513). * iommu/vt-d: Only warn about broken interrupt remapping (bnc#844513). * iommu: Remove stack trace from broken irq remapping warning (bnc#844513). * intel-iommu: Fix leaks in pagetable freeing (bnc#841402). * Revert aer_recover_queue() __GENKSYMS__ hack, add a fake symset with the previous value instead (bnc#847721). * i2c: ismt: initialize DMA buffer (bnc#843753). * powerpc/irq: Run softirqs off the top of the irq stack (bnc#847319). * quirks: add touchscreen that is dazzeled by remote wakeup (bnc#835930). * kernel: sclp console hangs (bnc#841498, LTC#95711). * tty/hvc_iucv: Disconnect IUCV connection when lowering DTR (bnc#839973,LTC#97595). * tty/hvc_console: Add DTR/RTS callback to handle HUPCL control (bnc#839973,LTC#97595). * softirq: reduce latencies (bnc#797526). * X.509: Remove certificate date checks (bnc#841656). * config/debug: Enable FSCACHE_DEBUG and CACHEFILES_DEBUG (bnc#837372). * splice: fix racy pipe->buffers uses (bnc#827246). * blktrace: fix race with open trace files and directory removal (bnc#832292). * rcu: Do not trigger false positive RCU stall detection (bnc#834204). * kernel: allow program interruption filtering in user space (bnc#837596, LTC#97332). * Audit: do not print error when LSMs disabled (bnc#842057). * SUNRPC: close a rare race in xs_tcp_setup_socket (bnc#794824). * Btrfs: fix negative ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise High Availability Extension 11-SP3, SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.3_02_3.0.101_0.8~0.7.9", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.3_02_3.0.101_0.8~0.7.9", rls:"SLES11.0SP3"))) {
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
