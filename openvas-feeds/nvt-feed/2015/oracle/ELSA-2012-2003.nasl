# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123956");
  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:48 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-2003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-2003");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-2003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-300.11.1.el5uek, mlnx_en-2.6.32-300.11.1.el6uek, ofa-2.6.32-300.11.1.el5uek, ofa-2.6.32-300.11.1.el6uek' package(s) announced via the ELSA-2012-2003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-300.11.1.el6uek]
- [fs] xfs: Fix possible memory corruption in xfs_readlink (Carlos Maiolino) {CVE-2011-4077}
- [scsi] increase qla2xxx firmware ready time-out (Joe Jin)
- [scsi] qla2xxx: Module parameter to control use of async or sync port login (Joe Jin)
- [net] tg3: Fix single-vector MSI-X code (Joe Jin)
- [net] qlge: fix size of external list for TX address descriptors (Joe Jin)
- [net] e1000e: Avoid wrong check on TX hang (Joe Jin)
- crypto: ghash - Avoid null pointer dereference if no key is set (Nick Bowler) {CVE-2011-4081}
- jbd/jbd2: validate sb->s_first in journal_get_superblock() (Eryu Guan) {CVE-2011-4132}
- KVM: Device assignment permission checks (Joe Jin) {CVE-2011-4347}
- KVM: x86: Prevent starting PIT timers in the absence of irqchip support (Jan Kiszka) {CVE-2011-4622}
- xfs: validate acl count (Joe Jin) {CVE-2012-0038}
- KVM: x86: fix missing checks in syscall emulation (Joe Jin) {CVE-2012-0045}
- KVM: x86: extend 'struct x86_emulate_ops' with 'get_cpuid' (Joe Jin) {CVE-2012-0045}
- igmp: Avoid zero delay when receiving odd mixture of IGMP queries (Ben Hutchings) {CVE-2012-0207}
- ipv4: correct IGMP behavior on v3 query during v2-compatibility mode (David Stevens)
- fuse: fix fuse request unique id (Srinivas Eeda) [orabug 13816349]

[2.6.32-300.10.1.el6uek]
- net: remove extra register in ip_gre (Guru Anbalagane) [Orabug: 13633287]

[2.6.32-300.9.1.el6uek]
- [netdrv] fnic: return zero on fnic_reset() success (Joe Jin)
- [e1000e] Add entropy generation back for network interrupts (John Sobecki)
- [nfs4] LINUX CLIENT TREATS NFS4ERR_GRACE AS A PERMANENT ERROR [orabug 13476821] (John Sobecki)
- [nfs] NFS CLIENT CONNECTS TO SERVER THEN DISCONNECTS [orabug 13516759] (John Sobecki)
- [sunrpc] Add patch for a mount crash in __rpc_create_common [orabug 13322773] (John Sobecki)

[2.6.32-300.8.1.el6uek]
- SPEC: fix dependency on firmware/mkinitrd (Guru Anbalagane) [orabug 13637902]
- xfs: fix acl count validation in xfs_acl_from_disk() (Dan Carpenter)
- [SCSI] scsi_dh: check queuedata pointer before proceeding further (Moger Babu)
 [orabug 13615419]");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-300.11.1.el5uek, mlnx_en-2.6.32-300.11.1.el6uek, ofa-2.6.32-300.11.1.el5uek, ofa-2.6.32-300.11.1.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.11.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.11.1.el5uek", rpm:"mlnx_en-2.6.32-300.11.1.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.11.1.el5uekdebug", rpm:"mlnx_en-2.6.32-300.11.1.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.11.1.el5uek", rpm:"ofa-2.6.32-300.11.1.el5uek~1.5.1~4.0.53", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.11.1.el5uekdebug", rpm:"ofa-2.6.32-300.11.1.el5uekdebug~1.5.1~4.0.53", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~300.11.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.11.1.el6uek", rpm:"mlnx_en-2.6.32-300.11.1.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-300.11.1.el6uekdebug", rpm:"mlnx_en-2.6.32-300.11.1.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.11.1.el6uek", rpm:"ofa-2.6.32-300.11.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-300.11.1.el6uekdebug", rpm:"ofa-2.6.32-300.11.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6"))) {
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
