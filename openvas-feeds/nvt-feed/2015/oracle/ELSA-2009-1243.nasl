# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122448");
  script_cve_id("CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-2847", "CVE-2009-2848");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:33 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1243)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1243");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1243.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-164.el5, oracleasm-2.6.18-164.el5' package(s) announced via the ELSA-2009-1243 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-164.el5]
- [misc] information leak in sigaltstack (Vitaly Mayatskikh ) [515396]
- [misc] execve: must clear current->clear_child_tid (Oleg Nesterov ) [515429]
- [net] igb: set lan id prior to configuring phy (Stefan Assmann ) [508870]
- [net] udp: socket NULL ptr dereference (Vitaly Mayatskikh ) [518043] {CVE-2009-2698}

[2.6.18-163.el5]
- [net] make sock_sendpage use kernel_sendpage (Danny Feng ) [516955] {CVE-2009-2692}

[2.6.18-162.el5]
- [x86_64] Intel IOMMU: Pass Through Support (Don Dutile ) [504363]

[2.6.18-161.el5]
- [dlm] free socket in error exit path (David Teigland ) [508829]
- [net] tg3: fix concurrent migration of VM clients (John Feeney ) [511918]
- [scsi] mptfusion: revert to pci_map (Tomas Henzl ) [514049]
- [scsi] bnx2i: fix conn disconnection bugs (mchristi@redhat.com ) [513802]
- [scsi] qla2xxx: unable to destroy npiv HBA ports (Marcus Barrow ) [514352]
- [scsi] ALUA: send STPG if explicit and implicit (mchristi@redhat.com ) [482737]
- [scsi] megaraid: fix the tape drive issue (Tomas Henzl ) [510665]
- [scsi] cxgb3i: fix skb allocation (mchristi@redhat.com ) [514073]
- [fs] __bio_clone: don't calculate hw/phys segment counts (Milan Broz ) [512387]
- [fs] ecryptfs: check tag 11 packet data buffer size (Eric Sandeen ) [512863] {CVE-2009-2406}
- [fs] ecryptfs: check tag 3 packet encrypted key size (Eric Sandeen ) [512887] {CVE-2009-2407}
- [xen] amd iommu: crash with pass-through on large memory (Bhavna Sarathy ) [514910]

[2.6.18-160.el5]
- [scsi] mptsas: fix max_id initialization (mchristi@redhat.com ) [455678]
- [ata] ahci: add IDs for Ibex Peak ahci controllers (David Milburn ) [513067]
- [scsi] lpfc: update to 8.2.0.48.2p, fix multiple panics (Rob Evers ) [512266]
- [gfs2] remove dcache entries for remote deleted inodes (Benjamin Marzinski ) [505548]
- [alsa] add native support for IbexPeak audio (Jaroslav Kysela ) [509526]
- [alsa] IbexPeak related patches for codec auto-config (Jaroslav Kysela ) [509526]
- [scsi] cciss: call bus_unregister in cciss_remove_one (Rob Evers ) [513070]
- [scsi] cciss: add driver sysfs entries (Rob Evers ) [513070]
- [net] e1000e/igb: make sure wol can be configured (Andy Gospodarek ) [513032]
- [fs] xfs: only compile for x86_64 (Eric Sandeen ) [512827]
- [ahci] add SATA GEN3 related messages (David Milburn ) [512086]
- [net] tun/tap: open /dev/net/tun and then poll() it fix (Danny Feng ) [512286] {CVE-2009-1897}
- [net] mlx4_en: problem with LRO that segfaults KVM host (Doug Ledford ) [510789]
- [openib] mthca: fix over sized kmalloc usage (Doug Ledford ) [508902]
- [s390] zcrypt: request gets timed out under high load (Hans-Joachim Picht ) [511289]

[2.6.18-159.el5]
- [scsi] cciss: fix sysfs broken symlink regression (Rob Evers ) [510178]
- [kabi] add consume_skb (Jon Masters ) [479200]
- [net] ipv6: fix incorrect disable_ipv6 behavior (jolsa@redhat.com ) [512258]
- [net] ipv6: fix BUG when disabled module is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-164.el5, oracleasm-2.6.18-164.el5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.el5", rpm:"ocfs2-2.6.18-164.el5~1.4.2~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.el5PAE", rpm:"ocfs2-2.6.18-164.el5PAE~1.4.2~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.el5debug", rpm:"ocfs2-2.6.18-164.el5debug~1.4.2~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-164.el5xen", rpm:"ocfs2-2.6.18-164.el5xen~1.4.2~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.el5", rpm:"oracleasm-2.6.18-164.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.el5PAE", rpm:"oracleasm-2.6.18-164.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.el5debug", rpm:"oracleasm-2.6.18-164.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-164.el5xen", rpm:"oracleasm-2.6.18-164.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
