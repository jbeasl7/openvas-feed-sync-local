# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123922");
  script_cve_id("CVE-2011-4086", "CVE-2012-1601");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:19 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0571");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0571.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2012-0571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-220.17.1.el6]
- [scsi] fcoe: Do not switch context in vport_delete callback (Neil Horman) [809388 806119]

[2.6.32-220.16.1.el6]
- Revert: [x86] Ivy Bridge kernel rdrand support (Jay Fenlason) [800268 696442]

[2.6.32-220.15.1.el6]
- [net] SUNRPC: We must not use list_for_each_entry_safe() in rpc_wake_up() (Steve Dickson) [811299 809928]
- [char] ipmi: Increase KCS timeouts (Matthew Garrett) [806906 803378]
- [kernel] sched: Fix ancient race in do_exit() (Frantisek Hrbata) [805457 784758]
- [scsi] sd: Unmap discard alignment needs to be converted to bytes (Mike Snitzer) [810322 805519]
- [scsi] sd: Fix VPD buffer allocations (Mike Snitzer) [810322 805519]
- [x86] Ivy Bridge kernel rdrand support (Jay Fenlason) [800268 696442]
- [scsi] fix system lock up from scsi error flood (Frantisek Hrbata) [809378 800555]
- [sound] ALSA: pcm midlevel code - add time check for (Jaroslav Kysela) [801329 798984]
- [pci] Add pcie_hp=nomsi to disable MSI/MSI-X for pciehp driver (hiro muneda) [807426 728852]
- [sound] ALSA: enable OSS emulation layer for PCM and mixer (Jaroslav Kysela) [812960 657291]
- [scsi] qla4xxx: Fixed BFS with sendtargets as boot index (Chad Dupuis) [803881 722297]
- [fs] nfs: Additional readdir cookie loop information (Steve Dickson) [811135 770250]
- [fs] NFS: Fix spurious readdir cookie loop messages (Steve Dickson) [811135 770250]
- [x86] powernow-k8: Fix indexing issue (Frank Arnold) [809391 781566]
- [x86] powernow-k8: Avoid Pstate MSR accesses on systems supporting CPB (Frank Arnold) [809391 781566]
- [redhat] spec: Add python-perf-debuginfo subpackage (Josh Boyer) [806859 806859]

[2.6.32-220.14.1.el6]
- [net] fix vlan gro path (Jiri Pirko) [810454 720611]
- [virt] VMX: vmx_set_cr0 expects kvm->srcu locked (Marcelo Tosatti) [808206 807507] {CVE-2012-1601}
- [virt] KVM: Ensure all vcpus are consistent with in-kernel irqchip settings (Marcelo Tosatti) [808206 807507] {CVE-2012-1601}
- [scsi] fcoe: Move destroy_work to a private work queue (Neil Horman) [809388 806119]
- [fs] jbd2: clear BH_Delay & BH_Unwritten in journal_unmap_buffer (Eric Sandeen) [749727 748713] {CVE-2011-4086}
- [net] af_iucv: offer new getsockopt SO_MSGSIZE (Hendrik Brueckner) [804547 786997]
- [net] af_iucv: performance improvements for new HS transport (Hendrik Brueckner) [804548 786996]
- [s390x] af_iucv: remove IUCV-pathes completely (Hendrik Brueckner) [807158 786960]
- [x86] iommu/amd: Fix wrong shift direction (Don Dutile) [809376 781531]
- [x86] iommu/amd: Don't use MSI address range for DMA addresses (Don Dutile) [809374 781524]
- [fs] NFSv4: Further reduce the footprint of the idmapper (Steve Dickson) [802852 730045]
- [fs] NFSv4: Reduce the footprint of the idmapper (Steve Dickson) [802852 730045]
- [scsi] fcoe: Make fcoe_transport_destroy a synchronous operation (Neil Horman) [809372 771251]
- [net] ipv4: Constrain UFO fragment sizes to multiples of 8 bytes (Jiri Benc) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.17.1.el6", rls:"OracleLinux6"))) {
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
