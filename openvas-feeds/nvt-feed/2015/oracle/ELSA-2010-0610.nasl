# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122332");
  script_cve_id("CVE-2010-1084", "CVE-2010-2066", "CVE-2010-2070", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2524");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 15:59:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2010-0610)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0610");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0610.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-194.11.1.0.1.el5, oracleasm-2.6.18-194.11.1.0.1.el5' package(s) announced via the ELSA-2010-0610 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-194.11.1.0.1.el5]
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

[2.6.18-194.11.1.el5]
- [scsi] qla2xxx: update firmware to version 5.03.02 (Chad Dupuis) [613688 598946]

[2.6.18-194.10.1.el5]
- [fs] xfs: don't let swapext operate on write-only files (Jiri Pirko) [605160 605161] {CVE-2010-2226}
- [fs] nfs: fix bug in nfsd4 read_buf (Jiri Olsa) [612034 612035] {CVE-2010-2521}
- [fs] cifs: reject DNS upcall add_key req from userspace (Jeff Layton) [612170 612171] {CVE-2010-2524}
- [security] keys: new key flag for add_key from userspace (Jeff Layton) [612170 612171] {CVE-2010-2524}
- [message] mptsas: fix disk add failing due to timeout (Rob Evers) [612539 542892]
- [block] cfq-iosched: fix bad locking in changed_ioprio (Jeff Moyer) [607483 582435]
- [block] cfq-iosched: kill cfq_exit_lock (Jeff Moyer) [607483 582435]
- [fs] cifs: fix kernel BUG with remote OS/2 server (Jeff Layton) [608587 608588] {CVE-2010-2248}
- [net] bluetooth: fix possible bad memory access via sysfs (Mauro Carvalho Chehab) [576020 576021] {CVE-2010-1084}
- [net] tcp: fix rcv mss estimate for lro (Stanislaw Gruszka) [613900 593801]
- [net] cnic: fix panic when nl msg rcvd when device down (Stanislaw Gruszka) [615260 595862]

[2.6.18-194.9.1.el5]
- [xen] ia64: unset be from the task psr (Andrew Jones) [587475 587477] {CVE-2010-2070}
- [fs] ext4: MOVE_EXT can't overwrite append-only files (Eric Sandeen) [601007 601008] {CVE-2010-2066}
- [pci] acpiphp: fix missing acpiphp_glue_exit (Prarit Bhargava) [607486 515556]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-194.11.1.0.1.el5, oracleasm-2.6.18-194.11.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.11.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.11.1.0.1.el5", rpm:"ocfs2-2.6.18-194.11.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.11.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-194.11.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.11.1.0.1.el5debug", rpm:"ocfs2-2.6.18-194.11.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.11.1.0.1.el5xen", rpm:"ocfs2-2.6.18-194.11.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.11.1.0.1.el5", rpm:"oracleasm-2.6.18-194.11.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.11.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-194.11.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.11.1.0.1.el5debug", rpm:"oracleasm-2.6.18-194.11.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.11.1.0.1.el5xen", rpm:"oracleasm-2.6.18-194.11.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
