# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122369");
  script_cve_id("CVE-2009-4027", "CVE-2009-4307", "CVE-2010-0727", "CVE-2010-1188");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:40 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0178)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0178");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0178.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-194.el5, oracleasm-2.6.18-194.el5' package(s) announced via the ELSA-2010-0178 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-194.el5]
- [net] mlx4: pass attributes down to vlan interfaces (Doug Ledford) [573098]
- [block] cfq-iosched: fix sequential read perf regression (Jeff Moyer) [571818]

[2.6.18-193.el5]
- [fs] gfs2: locking fix for potential dos (Steven Whitehouse) [572390] {CVE-2010-0727}
- [acpi] power_meter: avoid oops on driver load (Matthew Garrett) [566575]
- [net] r8169: fix assignments in backported net_device_ops (Ivan Vecera) [568040]
- [net] virtio_net: refill rx buffer on out-of-memory (Herbert Xu) [554078]

[2.6.18-192.el5]
- [cpu] fix amd l3 cache disable functionality (Jarod Wilson) [517586]
- [misc] backport upstream strict_strto* functions (Jarod Wilson) [517586]
- [wireless] rt2x00: fix work cancel race conditions (Stanislaw Gruszka) [562972]
- [net] igb: fix DCA support for 82580 NICs (Stefan Assmann) [513712]
- Revert: [ia64] kdump: fix a deadlock while redezvousing (Neil Horman) [506694]
- [block] cfq: kick busy queues w/o waiting for merged req (Jeff Moyer) [570814]
- [fs] cifs: max username len check in setup does not match (Jeff Layton) [562947]
- [fs] cifs: CIFS shouldn't make mountpoints shrinkable (Jeff Layton) [562947]
- [fs] cifs: fix dentry hash for case-insensitive mounts (Jeff Layton) [562947]
- [fs] cifs: fix len for converted unicode readdir names (Jeff Layton) [562947]
- [x86_64] xen: fix missing 32-bit syscalls on 64-bit Xen (Christopher Lalancette) [559410]
- [fs] gfs2: fix kernel BUG when using fiemap (Abhijith Das) [569610]
- [net] sctp: backport cleanups for ootb handling (Neil Horman) [555667] {CVE-2010-0008}
- [xen] vtd: ignore unknown DMAR entries (Don Dugger) [563900]

[2.6.18-191.el5]
- [wireless] iwlwifi: fix dual band N-only use on 5x00 (Stanislaw Gruszka) [566696]
- [net] be2net: critical bugfix from upstream (Ivan Vecera) [567718]
- [net] tg3: fix 5717 and 57765 asic revs panic under load (John Feeney) [565964]
- [net] bnx2x: use single tx queue (Stanislaw Gruszka) [567979]
- [net] igb: fix WoL initialization when disabled in eeprom (Stefan Assmann) [564102]
- [net] igb: fix warning in igb_ethtool.c (Stefan Assmann) [561076]
- [net] s2io: restore ability to tx/rx vlan traffic (Neil Horman) [562732]
- [net] ixgbe: stop unmapping DMA buffers too early (Andy Gospodarek) [568153]
- [net] e1000e: disable NFS filtering capabilities in ICH hw (Andy Gospodarek) [558809]
- [net] bnx2: update firmware and version to 2.0.8 (Andy Gospodarek) [561578]
- [net] mlx4: fix broken SRIOV code (Doug Ledford) [567730]
- [net] mlx4: pass eth attributes down to vlan interfaces (Doug Ledford) [557109]
- [x86_64] fix missing 32 bit syscalls on 64 bit (Wade Mealing) [559410]
- [s390] zcrypt: Do not remove coprocessor on error 8/72 (Hendrik Brueckner) [561067]
- [misc] usb-serial: add support for Qualcomm modems (Pete Zaitcev) [523888]
- [scsi] mpt2sas: fix missing initialization (Tomas Henzl) [565637]
- [i386] mce: avoid deadlocks during MCE broadcasts ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-194.el5, oracleasm-2.6.18-194.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.el5", rpm:"ocfs2-2.6.18-194.el5~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.el5PAE", rpm:"ocfs2-2.6.18-194.el5PAE~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.el5debug", rpm:"ocfs2-2.6.18-194.el5debug~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-194.el5xen", rpm:"ocfs2-2.6.18-194.el5xen~1.4.4~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.el5", rpm:"oracleasm-2.6.18-194.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.el5PAE", rpm:"oracleasm-2.6.18-194.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.el5debug", rpm:"oracleasm-2.6.18-194.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-194.el5xen", rpm:"oracleasm-2.6.18-194.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
