# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122732");
  script_cve_id("CVE-2014-7822", "CVE-2015-1805", "CVE-2015-6937");
  script_tag(name:"creation_date", value:"2015-11-16 14:06:42 +0000 (Mon, 16 Nov 2015)");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-3098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3098");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3098.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-118.el6uek, dtrace-modules-3.8.13-118.el7uek, kernel-uek' package(s) announced via the ELSA-2015-3098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-118]
- Update ql2400/ql2500 firmware version to 8.02.00 (Dan Duval) [Orabug: 22159505]
- update qla2400/ql2500 firmware version to 8.02.00 (Dan Duval) [Orabug: 22159505]

[3.8.13-117]
- virtio-net: drop NETIF_F_FRAGLIST (Jason Wang) [Orabug: 22145600] {CVE-2015-5156}
- team: check return value of team_get_port_by_index_rcu() for NULL (Jiri Pirko) [Orabug: 21944235]
- team: check return value of team_get_port_by_index_rcu() for NULL (Jiri Pirko) [Orabug: 21944235]

[3.8.13-116]
- team: check return value of team_get_port_by_index_rcu() for NULL (Jiri Pirko) [Orabug: 21944235]

[3.8.13-115]
- Disable VLAN 0 tagging for none VLAN traffic (Joe Jin) [Orabug: 20832922]
- x86/efi: Make efi virtual runtime map passing more robust (Borislav Petkov) [Orabug: 22020990]
- IB/rds_rdma: unloading of ofed stack causes page fault panic (Rama Nichanamatlu) [Orabug: 22039748]
- xen-blkfront: check for null drvdata in blkback_changed (XenbusStateClosing) (Cathy Avery) [Orabug: 21924428]

[3.8.13-114]
- rds: revert commit 4348013 (Rama Nichanamatlu) [Orabug: 22039425]
- qlcnic: Fix mailbox completion handling in spurious interrupt (Rajesh Borundia)
- xen-netfront: set max_queue default to 8 (Joe Jin) [Orabug: 21981690]
- xen-netfront: update num_queues to real created (Joe Jin) [Orabug: 21981690]
- lpfc: Update version to 11.0.0.1 for patch set (James Smart) [Orabug: 21860804]
- lpfc: Fix default RA_TOV and ED_TOV in the FC/FCoE driver for all topologies (James Smart) [Orabug: 21860804]
- lpfc: The linux driver does not reinitiate discovery after a failed FLOGI (James Smart) [Orabug: 21860804]
- lpfc: Fix for discovery failure in PT2PT when FLOGIs ELS ACC response gets aborted (James Smart) [Orabug: 21860804]
- lpfc: Add support for Lancer G6 and 32G FC links (James Smart) [Orabug: 21860804]
- fix: lpfc_send_rscn_event sends bigger buffer size (James Smart) [Orabug: 21860804]
- lpfc: Fix possible use-after-free and double free (James Smart) [Orabug: 21860804]
- lpfc: remove set but not used variables (James Smart) [Orabug: 21860804]
- lpfc: Make the function lpfc_sli4_mbox_completions_pending static (James Smart) [Orabug: 21860804]
- Fix kmalloc overflow in LPFC driver at large core count (James Smart) [Orabug: 21860804]
- lpfc: Destroy lpfc_hba_index IDR on module exit (James Smart) [Orabug: 21860804]
- lpfc: in sli3 use configured sg_seg_cnt for sg_tablesize (James Smart) [Orabug: 21860804]
- lpfc: Remove unnecessary cast (James Smart) [Orabug: 21860804]
- lpfc: fix model description (James Smart) [Orabug: 21860804]
- lpfc: Fix to drop PLOGIs from fabric node till LOGO proce ssing completes (James Smart) [Orabug: 21860804]
- lpfc: Fix scsi task management error message. (James Smart) [Orabug: 21860804]
- lpfc: Fix cq_id masking problem. (James Smart) [Orabug: 21860804]
- lpfc: Fix scsi prep dma buf error. (James Smart) [Orabug: 21860804]
- lpfc: Add support for using ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-118.el6uek, dtrace-modules-3.8.13-118.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.el6uek", rpm:"dtrace-modules-3.8.13-118.el6uek~0.4.5~3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-118.el7uek", rpm:"dtrace-modules-3.8.13-118.el7uek~0.4.5~3.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~118.el7uek", rls:"OracleLinux7"))) {
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
