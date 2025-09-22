# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123696");
  script_cve_id("CVE-2012-4508", "CVE-2012-4542", "CVE-2013-0190", "CVE-2013-0309", "CVE-2013-0310", "CVE-2013-0311");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0496)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0496");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0496.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-0496 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.el6]
- [fs] Fix sget() race with failing mount (Eric Sandeen) [883276]

[2.6.32-357.el6]
- [virt] xen: Fix stack corruption in xen_failsafe_callback for 32bit PVOPS guests (Andrew Jones) [896050] {CVE-2013-0190}
- [block] sg_io: use different default filters for each device class (Paolo Bonzini) [875361] {CVE-2012-4542}
- [block] sg_io: prepare for adding per-device-type filters (Paolo Bonzini) [875361] {CVE-2012-4542}
- [virt] virtio-blk: Don't free ida when disk is in use (Asias He) [870344]
- [netdrv] mlx4: Remove FCS bytes from packet length (Doug Ledford) [893707]
- [net] netfilter: nf_ct_reasm: fix conntrack reassembly expire code (Amerigo Wang) [726807]

[2.6.32-356.el6]
- [char] ipmi: use a tasklet for handling received messages (Prarit Bhargava) [890160]
- [char] ipmi: handle run_to_completion properly in deliver_recv_msg() (Prarit Bhargava) [890160]
- [usb] xhci: Reset reserved command ring TRBs on cleanup (Don Zickus) [843520]
- [usb] xhci: handle command after aborting the command ring (Don Zickus) [874541]
- [usb] xhci: cancel command after command timeout (Don Zickus) [874541]
- [usb] xhci: add aborting command ring function (Don Zickus) [874541]
- [usb] xhci: add cmd_ring_state (Don Zickus) [874541]
- [usb] xhci: Fix Null pointer dereferencing with non-DMI systems (Don Zickus) [874542]
- [usb] xhci: Intel Panther Point BEI quirk (Don Zickus) [874542]
- [usb] xhci: Increase XHCI suspend timeout to 16ms (Don Zickus) [874542]
- [powerpc] Revert: pseries/iommu: remove default window before attempting DDW manipulation (Steve Best) [890454]
- [serial] 8250_pnp: add Intermec CV60 touchscreen device (Mauro Carvalho Chehab) [894445]
- [char] ipmi: apply missing hunk from upstream commit 2407d77a (Tony Camuso) [882787]
- [acpi] Fix broken kernel build if CONFIG_ACPI_DEBUG is enabled (Lenny Szubowicz) [891948]
- [scsi] qla2xxx: Test and clear FCPORT_UPDATE_NEEDED atomically (Chad Dupuis) [854736]
- [mm] vmalloc: remove guard page from between vmap blocks (Johannes Weiner) [873737]
- [mm] vmalloc: vmap area cache (Johannes Weiner) [873737]
- [fs] vfs: prefer EEXIST to EROFS when creating on an RO filesystem (Eric Sandeen) [878091]
- [scsi] qla2xxx: change queue depth ramp print to debug print (Rob Evers) [893113]
- [fs] nfs: Fix umount when filelayout DS is also the MDS (Steve Dickson) [895194]
- [fs] nfs/pnfs: add set-clear layoutdriver interface (Steve Dickson) [895194]
- [fs] nfs: Don't call nfs4_deviceid_purge_client() unless we're NFSv4.1 (Steve Dickson) [895194]
- [fs] nfs: Wait for session recovery to finish before returning (Steve Dickson) [895176]
- [mm] compaction: validate pfn range passed to isolate_freepages_block (Johannes Weiner) [889456 890498]
- [drm] nouveau: ensure legacy vga is re-enabled during POST (Ben Skeggs) [625441]
- [netdrv] be2net: Remove stops to further access to BE NIC on UE bits (Ivan Vecera) [894344]
- [virt] kvm: invalid ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.el6", rls:"OracleLinux6"))) {
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
