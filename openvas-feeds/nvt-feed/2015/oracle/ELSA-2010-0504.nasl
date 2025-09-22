# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122349");
  script_cve_id("CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:17 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:38:32 +0000 (Fri, 02 Feb 2024)");

  script_name("Oracle: Security Advisory (ELSA-2010-0504)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0504");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0504.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-194.8.1.0.1.el5, oracleasm-2.6.18-194.8.1.0.1.el5' package(s) announced via the ELSA-2010-0504 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-194.8.1.0.1.el5]
- [xen] check to see if hypervisor supports memory reservation change
 (Chuck Anderson) [orabug 7556514]
- Add entropy support to igb (John Sobecki) [orabug 7607479]
- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]
- [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043]
 [bz 7258]
- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [nfsd] fix failure of file creation from hpux client (Wen gang Wang)
 [orabug 7579314]
- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]
- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524]
- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105]
 RDS: Fix BUG_ONs to not fire when in a tasklet
 ipoib: Fix lockup of the tx queue
 RDS: Do not call set_page_dirty() with irqs off (Sherman Pun)
 RDS: Properly unmap when getting a remote access error (Tina Yang)
 RDS: Fix locking in rds_send_drop_to()
- [mm] Enahance shrink_zone patch allow full swap utilization, and also be
 NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh)
 [orabug 9245919]

[2.6.18-194.8.1.el5]
- [net] cnic: fix bnx2x panic w/multiple interfaces enabled (Stanislaw Gruszka) [607087 602402]

[2.6.18-194.7.1.el5]
- [virt] don't compute pvclock adjustments if we trust tsc (Glauber Costa) [601080 570824]
- [virt] add a global synchronization point for pvclock (Glauber Costa) [601080 570824]
- [virt] enable pvclock flags in vcpu_time_info structure (Glauber Costa) [601080 570824]
- [misc] add atomic64_cmpxcgh to x86_64 include files (Glauber Costa) [601080 570824]
- [x86] grab atomic64 types from upstream (Glauber Costa) [601080 570824]

[2.6.18-194.6.1.el5]
- [fs] gfs2: fix permissions checking for setflags ioctl (Steven Whitehouse) [595580 595399] {CVE-2010-1641}
- [mm] clear page errors when issuing a fresh read of page (Rik van Riel) [599739 590763]
- [misc] keys: do not find already freed keyrings (Vitaly Mayatskikh) [585099 585100] {CVE-2010-1437}
- [net] sctp: file must be valid before setting timeout (Jiri Pirko) [598355 578261]
- [net] tg3: fix panic in tg3_interrupt (John Feeney) [600498 569106]
- [net] e1000/e1000e: implement simple interrupt moderation (Andy Gospodarek) [599332 586416]
- [net] cnic: Fix crash during bnx2x MTU change (Stanislaw Gruszka) [596385 582367]
- [net] bxn2x: add dynamic lro disable support (Stanislaw Gruszka) [596385 582367]
- [net] implement dev_disable_lro api for RHEL5 (Stanislaw Gruszka) [596385 582367]
- [x86_64] fix time drift due to faulty lost tick tracking (Ulrich Obergfell) [601090 579711]
- [net] neigh: fix state transitions via Netlink request (Jiri Pirko) [600215 485903]
- [mm] fix hugepage corruption using vm.drop_caches (Larry Woodman) [599737 579469]
- [nfs] don't unhash dentry in nfs_lookup_revalidate (Jeff Layton) [596384 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-194.8.1.0.1.el5, oracleasm-2.6.18-194.8.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.8.1.0.1.el5", rpm:"ocfs2-2.6.18-194.8.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.8.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-194.8.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.8.1.0.1.el5debug", rpm:"ocfs2-2.6.18-194.8.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.8.1.0.1.el5xen", rpm:"ocfs2-2.6.18-194.8.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.8.1.0.1.el5", rpm:"oracleasm-2.6.18-194.8.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.8.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-194.8.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.8.1.0.1.el5debug", rpm:"oracleasm-2.6.18-194.8.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.8.1.0.1.el5xen", rpm:"oracleasm-2.6.18-194.8.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
