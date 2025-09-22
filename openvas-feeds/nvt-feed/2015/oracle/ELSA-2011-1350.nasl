# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122078");
  script_cve_id("CVE-2011-1160", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1833", "CVE-2011-2022", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2521", "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-2918");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:42 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:19:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-1350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1350");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1350.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-1350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.17.1.el6]
- Revert: [net] ipv6: make fragment identifications less predictable (Jiri Pirko) [723432 723433] {CVE-2011-2699}

[2.6.32-131.16.1.el6]
- [net] br_multicast: Ensure to initialize BR_INPUT_SKB_CB(skb)->mrouters_only. (Frantisek Hrbata) [739477 738110]

[2.6.32-131.15.1.el6]
- rebuild

[2.6.32-131.14.1.el6]
- [scsi] megaraid_sas: Convert 6, 10, 12 byte CDB's for FastPath IO (Tomas Henzl) [710047 705835]
- [x86] perf, x86: Fix Intel fixed counters base initialization (Don Zickus) [719229 736284] {CVE-2011-2521}
- [net] ipv6: make fragment identifications less predictable (Jiri Pirko) [723432 723433] {CVE-2011-2699}
- [fs] Ecryptfs: Add mount option to check uid of device being mounted = expect uid (Eric Sandeen) [731175 731176] {CVE-2011-1833}
- [char] tpm: Fix uninitialized usage of data buffer (Stanislaw Gruszka) [684674 684675] {CVE-2011-1160}
- [kernel] perf: Fix software event overflow (Frantisek Hrbata) [730707 730708] {CVE-2011-2918}
- [serial] 8250_pci: ifdef for powerpc, to only add functionality to this arch (Steve Best) [732382 696695]
- [serial] 8250: Fix capabilities when changing the port type (Steve Best) [732382 696695]
- [serial] 8250_pci Add EEH support to the 8250 driver for IBM/Digi PCIe 2-port Adapter (Steve Best) [732382 696695]
- [serial] 8250_pci: Add support for the Digi/IBM PCIe 2-port Adapter (Steve Best) [732382 696695]
- [ppc] pseries/iommu: Add additional checks when changing iommu mask (Steve Best) [736065 704401]
- [ppc] pseries/iommu: Use correct return type in dupe_ddw_if_already_created (Steve Best) [736065 704401]
- [ppc] iommu: Restore iommu table pointer when restoring iommu ops (Steve Best) [736065 704401]
- [ppc] Fix kexec with dynamic dma windows (Steve Best) [736065 704401]

[2.6.32-131.13.1.el6]
- [net] af_packet: prevent information leak (Jiri Pirko) [728032 728033] {CVE-2011-2898}
- [net] gro: Only reset frag0 when skb can be pulled (Jiri Pirko) [726555 726556] {CVE-2011-2723}
- [fs] FS-Cache: Only call mark_tech_preview() when caching is actually begun (David Howells) [713463 696396]
- [fs] Fix mark_tech_preview() to not disable lock debugging (David Howells) [713463 696396]
- [fs] ext4: Rewrite ext4_page_mkwrite() to use generic helpers (Eric Sandeen) [723551 692167]
- [fs] vfs: Block mmapped writes while the fs is frozen (Eric Sandeen) [723551 692167]
- [fs] vfs: Create __block_page_mkwrite() helper passing error values back (Eric Sandeen) [723551 692167]
- [mm] avoid wrapping vm_pgoff in mremap() and stack expansion (Jerome Marchand) [716540 716541] {CVE-2011-2496}
- [pci] MSI: Restore read_msi_msg_desc(), add get_cached_msi_msg_desc() (Don Zickus) [728522 696511]
- [pci] MSI: Remove unsafe and unnecessary hardware access (Don Zickus) [728522 696511]
- [net] sock: do not change prot->obj_size (Jiri Pirko) [726626 725711]
- [virt] x86: report valid microcode update ID (Marcelo Tosatti) [727838 694747]
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.17.1.el6", rls:"OracleLinux6"))) {
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
