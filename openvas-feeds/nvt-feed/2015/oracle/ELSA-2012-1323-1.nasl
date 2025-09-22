# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123807");
  script_cve_id("CVE-2012-2319", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3510");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:49 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2012-1323-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1323-1");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1323-1.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-308.16.1.0.1.el5, oracleasm-2.6.18-308.16.1.0.1.el5' package(s) announced via the ELSA-2012-1323-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel
[2.6.18-308.16.1.0.1.el5]
- [kernel] Initialize the local uninitialized variable stats. [orabug 14051367]
- [fs] JBD:make jbd support 512B blocks correctly for ocfs2. [orabug 13477763]
- [x86 ] fix fpu context corrupt when preempt in signal context [orabug 14038272]
- [net] bonding: fix carrier detect when bond is down [orabug 12377284]
- [mm] fix hugetlb page leak (Dave McCracken) [orabug 12375075]
- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)
- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)
- [x86] Fix lvt0 reset when hvm boot up with noapic param
- [scsi] remove printks when doing I/O to a dead device (John Sobecki, Chris Mason)
 [orabug 12342275]
- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]
- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]
- [net] net: Redo the broken redhat netconsole over bonding (Tina Yang) [orabug 12740042]
- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]
- [scsi] fix scsi hotplug and rescan race [orabug 10260172]
- fix filp_close() race (Joe Jin) [orabug 10335998]
- make xenkbd.abs_pointer=1 by default [orabug 67188919]
- [xen] check to see if hypervisor supports memory reservation change
 (Chuck Anderson) [orabug 7556514]
- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki)
 [orabug 10315433]
- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]
- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]
- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]
- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105]
 RDS: Fix BUG_ONs to not fire when in a tasklet
 ipoib: Fix lockup of the tx queue
 RDS: Do not call set_page_dirty() with irqs off (Sherman Pun)
 RDS: Properly unmap when getting a remote access error (Tina Yang)
 RDS: Fix locking in rds_send_drop_to()
- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson)
 [orabug 9107465]
- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson)
 [orabug 9764220]
- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]
- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro,
 Guru Anbalagane) [orabug 6124033]
- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]
- [ib] fix memory corruption (Andy Grover) [orabug 9972346]

[2.6.18-308.16.1.el5]
- Revert: [fs] nfsd4: Remove check for a 32-bit cookie in nfsd4_readdir() (Eric Sandeen) [847943 784191]
- Revert: [fs] add new FMODE flags: FMODE_32bithash and FMODE_64bithash (Eric Sandeen) [847943 784191]
- Revert: [fs] nfsd: rename int access to int may_flags in nfsd_open() (Eric Sandeen) [847943 784191]
- Revert: [fs] nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes) (Eric Sandeen) [847943 784191]
- Revert: [fs] vfs: add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-308.16.1.0.1.el5, oracleasm-2.6.18-308.16.1.0.1.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.16.1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.0.1.el5", rpm:"ocfs2-2.6.18-308.16.1.0.1.el5~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.0.1.el5PAE", rpm:"ocfs2-2.6.18-308.16.1.0.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.0.1.el5debug", rpm:"ocfs2-2.6.18-308.16.1.0.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-308.16.1.0.1.el5xen", rpm:"ocfs2-2.6.18-308.16.1.0.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.0.1.el5", rpm:"oracleasm-2.6.18-308.16.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.0.1.el5PAE", rpm:"oracleasm-2.6.18-308.16.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.0.1.el5debug", rpm:"oracleasm-2.6.18-308.16.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-308.16.1.0.1.el5xen", rpm:"oracleasm-2.6.18-308.16.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
