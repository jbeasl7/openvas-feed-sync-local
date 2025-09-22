# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0189.1");
  script_cve_id("CVE-2013-2146", "CVE-2013-2930", "CVE-2013-4345", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4587", "CVE-2013-4592", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6383", "CVE-2013-6463", "CVE-2013-7027");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0189-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0189-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140189-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2014:0189-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to 3.0.101 and also includes various other bug and security fixes.

A new feature was added:

 * supported.conf: marked net/netfilter/xt_set as supported (bnc#851066)(fate#313309)

The following security bugs have been fixed:

 *

 CVE-2013-4587: Array index error in the kvm_vm_ioctl_create_vcpu function in virt/kvm/kvm_main.c in the KVM subsystem in the Linux kernel through 3.12.5 allows local users to gain privileges via a large id value.
(bnc#853050)

 *

 CVE-2013-4592: Memory leak in the __kvm_set_memory_region function in virt/kvm/kvm_main.c in the Linux kernel before 3.9 allows local users to cause a denial of service (memory consumption) by leveraging certain device access to trigger movement of memory slots.
(bnc#851101)

 *

 CVE-2013-6367: The apic_get_tmcct function in arch/x86/kvm/lapic.c in the KVM subsystem in the Linux kernel through 3.12.5 allows guest OS users to cause a denial of service (divide-by-zero error and host OS crash)
via crafted modifications of the TMICT value. (bnc#853051)

 *

 CVE-2013-6368: The KVM subsystem in the Linux kernel through 3.12.5 allows local users to gain privileges or cause a denial of service (system crash) via a VAPIC synchronization operation involving a page-end address.
(bnc#853052)

 *

 CVE-2013-6376: The recalculate_apic_map function in arch/x86/kvm/lapic.c in the KVM subsystem in the Linux kernel through 3.12.5 allows guest OS users to cause a denial of service (host OS crash) via a crafted ICR write operation in x2apic mode. (bnc#853053)

 *

 CVE-2013-4483: The ipc_rcu_putref function in ipc/util.c in the Linux kernel before 3.10 does not properly manage a reference count, which allows local users to cause a denial of service (memory consumption or system crash) via a crafted application. (bnc#848321)

 *

 CVE-2013-4511: Multiple integer overflows in Alchemy LCD frame-buffer drivers in the Linux kernel before 3.12 allow local users to create a read-write memory mapping for the entirety of kernel memory, and consequently gain privileges, via crafted mmap operations, related to the (1)
au1100fb_fb_mmap function in drivers/video/au1100fb.c and the (2) au1200fb_fb_mmap function in drivers/video/au1200fb.c. (bnc#849021)

 *

 CVE-2013-4514: Multiple buffer overflows in drivers/staging/wlags49_h2/wl_priv.c in the Linux kernel before 3.12 allow local users to cause a denial of service or possibly have unspecified other impact by leveraging the CAP_NET_ADMIN capability and providing a long station-name string, related to the (1) wvlan_uil_put_info and (2)
wvlan_set_station_nickname functions. (bnc#849029)

 *

 CVE-2013-4515: The bcm_char_ioctl function in drivers/staging/bcm/Bcmchar.c in the Linux kernel before 3.12 does not initialize a certain data structure, which allows local users to obtain sensitive information from kernel memory via an ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.15.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.3_08_3.0.101_0.15~0.7.22", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.3_08_3.0.101_0.15~0.7.22", rls:"SLES11.0SP3"))) {
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
