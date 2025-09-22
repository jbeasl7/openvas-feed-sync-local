# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122103");
  script_cve_id("CVE-2011-1182", "CVE-2011-1576", "CVE-2011-1593", "CVE-2011-1776", "CVE-2011-1898", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-2689", "CVE-2011-2695");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:08 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 20:22:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-1189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1189");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1189.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-1189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.12.1.el6]
- [netdrv] be2net: clear intr bit in be_probe() (Ivan Vecera) [726308 722596]

[2.6.32-131.11.1.el6]
- [mm] hold the page lock until after set_page_stable_node (Andrea Arcangeli) [726095 683658]
- [netdrv] be2net: remove certain cmd failure logging (Ivan Vecera) [725329 719304]
- [net] nl80211: missing check for valid SSID size in scan operation (Stanislaw Gruszka) [718157 718158] {CVE-2011-2517}
- [net] bluetooth: l2cap and rfcomm: fix 1 byte infoleak to userspace. (Thomas Graf) [703022 703023] {CVE-2011-2492}
- [net] inet_diag: fix validation of user data in inet_diag_bc_audit() (Thomas Graf) [714540 714541] {CVE-2011-2213}
- [fs] proc: restrict access to /proc/PID/io (Oleg Nesterov) [716829 716830] {CVE-2011-2495}
- [fs] validate size of EFI GUID partition entries (Anton Arapov) [703029 703030] {CVE-2011-1776}
- [fs] ext4: Fix max file size and logical block counting of extent format file (Lukas Czerner) [722568 722569] {CVE-2011-2695}
- [virt] kvm: Disable device assignment without interrupt remapping (Alex Williamson) [716306 711504] {CVE-2011-1898}
- [virt] iommu-api: Extension to check for interrupt remapping (Alex Williamson) [716306 711504] {CVE-2011-1898}
- [netdrv] r8169: fix Rx checksum offloading bugs (Ivan Vecera) [723807 635596]
- [netdrv] be2net: changes for BE3 native mode support (Ivan Vecera) [723820 695231]

[2.6.32-131.10.1.el6]
- [virt] ksm: fix race between ksmd and exiting task (Andrea Arcangeli) [710340 710341] {CVE-2011-2183}
- [kernel] proc: signedness issue in next_pidmap() (Jerome Marchand) [697824 697825] {CVE-2011-1593}
- [net] bluetooth: Prevent buffer overflow in l2cap config request (Jiri Pirko) [716809 716810] {CVE-2011-2497}
- [fs] NLM: Don't hang forever on NLM unlock requests (Jeff Layton) [709548 709549] {CVE-2011-2491}
- [fs] NFS: Fix NFSv3 exclusive open semantics (Jeff Layton) [719925 694210]
- [fs] GFS2: Incorrect inode state during deallocation (Steven Whitehouse) [714982 712139]
- [virt] KVM: Fix register corruption in pvclock_scale_delta (Avi Kivity) [719910 712102]
- [netdrv] ehea: Fix memory hotplug oops (Steve Best) [720914 702036]
- [net] Fix memory leak/corruption on VLAN GRO_DROP (Herbert Xu) [695175 695176] {CVE-2011-1576}
- [md] Fix resync hang after surprise removal (James Paradis) [719928 707268]
- GFS2: make sure fallocate bytes is a multiple of blksize (Benjamin Marzinski) [720863 695763] {CVE-2011-2689}
- [kernel] Prevent rt_sigqueueinfo and rt_tgsigqueueinfo from spoofing the signal code (Oleg Nesterov) [715521 690033] {CVE-2011-1182}
- [redhat] config: enable parallel port printer support (Aristeu Rozanski) [713827 635968]

[2.6.32-131.9.1.el6]
- [scsi] cciss: Annotate cciss_kdump_soft_reset and cciss_sent_reset as __devinit (Tomas Henzl) [715397 698268]
- [scsi] cciss: Don't wait forever for soft reset to complete, give up after awhile (Tomas Henzl) [715397 698268]
- [scsi] cciss: use ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.12.1.el6", rls:"OracleLinux6"))) {
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
