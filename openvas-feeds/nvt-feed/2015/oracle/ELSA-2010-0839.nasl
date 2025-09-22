# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122298");
  script_cve_id("CVE-2010-3066", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3086", "CVE-2010-3448", "CVE-2010-3477");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 14:45:00 +0000 (Tue, 11 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2010-0839)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0839");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0839.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-194.26.1.0.1.el5, oracleasm-2.6.18-194.26.1.0.1.el5' package(s) announced via the ELSA-2010-0839 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-194.26.1.0.1.el5]
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
- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin)
 [orabug 9504524]
- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105]
 RDS: Fix BUG_ONs to not fire when in a tasklet
 ipoib: Fix lockup of the tx queue
 RDS: Do not call set_page_dirty() with irqs off (Sherman Pun)
 RDS: Properly unmap when getting a remote access error (Tina Yang)
 RDS: Fix locking in rds_send_drop_to()
- [mm] Enhance shrink_zone patch allow full swap utilization, and also be
 NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh)
 [orabug 9245919]
- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson)
 [orabug 9107465]
- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson)
 [orabug 9764220]
- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]
- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro,
 Guru Anbalagane) [orabug 6124033]
- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]
- [ib] fix memory corruption (Andy Grover) [orabug 9972346]

[2.6.18-194.26.1.el5]
- [net] mlx4: bump max log_mtts_per_seg memory reservation (Jay Fenlason) [643806 636198]

[2.6.18-194.25.1.el5]
- [fs] nfs: fix regression in NFS Direct I/O path (Steve Dickson) [647601 647297]

[2.6.18-194.24.1.el5]
- Changelog fix

[2.6.18-194.23.1.el5]
- [net] bonding: correctly process non-linear skbs (Andy Gospodarek) [644822 619070]
- Syncing following patch from branched build:
- [net] rds: fix local privilege escalation (Eugene Teo) [642897 642898] {CVE-2010-3904}

[2.6.18-194.22.1.el5]
- [fs] xfs: fix speculative allocation beyond eof (Dave Chinner) [643571 638753]

[2.6.18-194.21.1.el5]
- [scsi] qla2xxx: Correct use-after-free issue in terminate_rport_io callback
 (Chad Dupuis) [643135 567428]
- [misc] futex: replace LOCK_PREFIX in futex.h (Peter Zijlstra) [633175 633176]
 {CVE-2010-3086}
- [v4l] remove compat code for VIDIOCSMICROCODE (Mauro Carvalho Chehab) [642470
 642471] {CVE-2010-2963}
- [xen] hvm: correct accuracy of pmtimer (Andrew Jones) [641915 633028]
- [net] bonding: fix IGMP report on slave during failover (Flavio Leitner) [640973
 637764]
- [fs] nfsv4: fix bug when server returns NFS4ERR_RESOURCE (Steve Dickson) [628889
 620502]
- [fs] nfsv4: ensure lockowners are labelled ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-194.26.1.0.1.el5, oracleasm-2.6.18-194.26.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.26.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.26.1.0.1.el5", rpm:"ocfs2-2.6.18-194.26.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.26.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-194.26.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.26.1.0.1.el5debug", rpm:"ocfs2-2.6.18-194.26.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.26.1.0.1.el5xen", rpm:"ocfs2-2.6.18-194.26.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.26.1.0.1.el5", rpm:"oracleasm-2.6.18-194.26.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.26.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-194.26.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.26.1.0.1.el5debug", rpm:"oracleasm-2.6.18-194.26.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.26.1.0.1.el5xen", rpm:"oracleasm-2.6.18-194.26.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
