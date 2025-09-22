# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123968");
  script_cve_id("CVE-2011-1083");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-0150)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0150");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0150.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.el5, oracleasm-2.6.18-308.el5' package(s) announced via the ELSA-2012-0150 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-308.el5]
- [scsi] lpfc: Update lpfc version for 8.2.0.108.4p driver release (Rob Evers) [784073]
- [scsi] lpfc: Fix FCP EQ memory check init w/single int vector (Rob Evers) [784073]

[2.6.18-307.el5]
- [s390] crypto: Reset sha2 index after processing partial block (David Howells) [677860]
- Revert: [fs] xfs: implement ->dirty_inode to fix timestamp (Eric Sandeen) [653215]

[2.6.18-306.el5]
- [s390] pfault: ignore leftover completion interrupts (Jarod Wilson) [753194]
- [cpufreq] powernow-k8: Fix indexing issue (Frank Arnold) [782773]
- [scsi] device_handler: optimize transition retries (Rob Evers) [733635]
- [net] qlge: fix size of external list for TX address descriptors (Chad Dupuis) [772696]
- [net] igmp: Avoid zero delay when rx'ing odd mix of IGMP queries (Jiri Pirko) [772869]
- [net] be2net: create RSS rings even in multi-channel configs (Ivan Vecera) [773114]
- [net] ipv6: track device renames in snmp6 (Andy Gospodarek) [758923]
- [fs] jbd2: clear BH_Delay & BH_Unwritten in journal_unmap_buffer (Eric Sandeen) [783284] {CVE-2011-4086}
- [fs] epoll: workarounds to preserve kernel ABI (Jason Baron) [681692] {CVE-2011-1083}
- [fs] epoll: limit paths (Jason Baron) [681692] {CVE-2011-1083}
- [fs] epoll: prevent creating circular epoll structures (Jason Baron) [681692] {CVE-2011-1083}
- [fs] epoll: add ep_call_nested() (Jason Baron) [681692] {CVE-2011-1083}
- [fs] gfs2: additional fix for inode allocation error path (Robert S Peterson) [767377]
- [fs] gfs2: Revert clean up fsync changes (Robert S Peterson) [767377]
- [fs] ext4: ignore EXT4_INODE_JOURNAL_DATA flag with delalloc (Lukas Czerner) [769386]
- [mm] filemap: Make write(2) interruptible by a fatal signal (Lukas Czerner) [740898]
- [mm] Make task in balance_dirty_pages killable (Lukas Czerner) [740898]
- [fs] ext4: fix the deadlock in mpage_da_map_and_submit (Lukas Czerner) [740898]
- [fs] ext4: fix deadlock in ext4_ordered_write_end (Lukas Czerner) [740898]
- [fs] ext4: mark multi-page IO complete on mapping failure (Lukas Czerner) [740898]
- [fs] ext4: make invalidate pages handle page range properly (Lukas Czerner) [740898]
- [fs] ext4: call mpage_da_submit_io from mpage_da_map_blocks (Lukas Czerner) [740898]
- [fs] nfsd: Avoid excess stack usage in svc_tcp_recvfrom (J. Bruce Fields) [765751]
- [fs] nfsd: Replace two page lists in struct svc_rqst with one (J. Bruce Fields) [765751]

[2.6.18-305.el5]
- [edac] i5000: don't crash before showing the edac error (Mauro Carvalho Chehab) [713034]
- [Documentation] Add pci=noseg to kernel-parameters.txt (Prarit Bhargava) [743168]
- [net] ipv6: fix tcp_v6_conn_request (Jiri Benc) [714670]
- [redhat] update RHEL_MINOR to 8 for 5.8 release (Jarod Wilson) [773033]
- [misc] Move exit_robust_list to mm_release, null lists on cleanup (Laszlo Ersek) [750283] {CVE-2012-0028}
- [fs] nfs: Fix an O_DIRECT Oops (Jeff Layton) [754620] {CVE-2011-4325}
- [xen] x86: fix a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.el5, oracleasm-2.6.18-308.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.el5", rpm:"ocfs2-2.6.18-308.el5~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.el5PAE", rpm:"ocfs2-2.6.18-308.el5PAE~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.el5debug", rpm:"ocfs2-2.6.18-308.el5debug~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.el5xen", rpm:"ocfs2-2.6.18-308.el5xen~1.4.9~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.el5", rpm:"oracleasm-2.6.18-308.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.el5PAE", rpm:"oracleasm-2.6.18-308.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.el5debug", rpm:"oracleasm-2.6.18-308.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.el5xen", rpm:"oracleasm-2.6.18-308.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
