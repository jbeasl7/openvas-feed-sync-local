# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122162");
  script_cve_id("CVE-2010-3881", "CVE-2010-4251", "CVE-2010-4805", "CVE-2011-0999", "CVE-2011-1010", "CVE-2011-1023", "CVE-2011-1082", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1581");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:05 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 17:52:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0542)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0542");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0542.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0542 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.0.15.el6]
- [build] disable Werr for external modules (Aristeu Rozanski) [703504]

[2.6.32-131.0.14.el6]
- [scsi] hpsa: fix reading a write only register causes a hang (Rob Evers) [703262]
- [scsi] mpt2sas: remove the use of writeq, since writeq is not atomic (Tomas Henzl) [701947]

[2.6.32-131.0.13.el6]
- [scsi] hpsa: fix lost command problem (Tomas Henzl) [700430]
- [scsi] cciss: fix lost command problem (Tomas Henzl) [700430]
- [scsi] ibft: fix oops during boot (Mike Christie) [698737]

[2.6.32-131.0.12.el6]
- [scsi] beiscsi: update version (Mike Christie) [674340]
- [scsi] be2iscsi: fix chip cleanup (Mike Christie) [674340]
- [scsi] be2iscsi: fix boot hang due to interrupts not getting rearmed (Mike Christie) [674340]
- [scsi] bnx2fc: fix regression due to incorrect setup of em for npiv port (Mike Christie) [700672]
- [ppc] pseries: Use a kmem cache for DTL buffers (Steve Best) [695678]

[2.6.32-131.0.11.el6]
- [kdump] revert commit 8f4ec27fc to keep crashkernel=auto (Amerigo Wang) [605786]

[2.6.32-131.0.10.el6]
- [netdrv] cnic: fix hang due to rtnl_lock (Mike Christie) [694874]
- [netdrv] firmware: re-add the recently deleted bnx2x fw 6.2.5.0 (Michal Schmidt) [690470]
- [netdrv] firmware/bnx2x: add 6.2.9.0 fw, remove unused fw (Michal Schmidt) [690470]
- [netdrv] bnx2x, cnic: Disable iSCSI if DCBX negotiation is successful (Michal Schmidt) [690470]
- [netdrv] bnx2x: don't write dcb/llfc fields in STORM memory (Michal Schmidt) [690470]
- [netdrv] bnx2x: Update firmware to 6.2.9 (Michal Schmidt) [690470]

[2.6.32-131.0.9.el6]
- [net] limit socket backlog add operation to prevent possible DoS (Jiri Pirko) [694396] {CVE-2010-4251}
- [scsi] mpt2sas: prevent heap overflows and unchecked (Tomas Henzl) [694023] {CVE-2011-1494 CVE-2011-1495}
- [fs] epoll: prevent creating circular epoll structures (Don Howard) [681683] {CVE-2011-1082}
- [mm] Prevent page_fault at do_mm_track_pte+0xc when Stratus dirty page tracking is active (Larry Woodman) [693786]
- [fs] GFS2 causes kernel panic in spectator mode (Steven Whitehouse) [696535]
- [net] bonding: interface doesn't issue IGMP report on slave interface during failover (Flavio Leitner) [640690]
- [scsi] isci: validate oem parameters early, and fallback (David Milburn) [698016]
- [scsi] isci: fix oem parameter header definition (David Milburn) [698016]

[2.6.32-131.0.8.el6]
- [scsi] mark bfa fc adapters tech preview (Rob Evers) [698384]
- [virt] Revert pdpte registers are not flushed when PGD entry is changed in x86 PAE mode (Aristeu Rozanski) [691310]
- [i686] nmi watchdog: Enable panic on hardlockup (Don Zickus) [677532]
- [netdrv] Adding Chelsio Firmware for cxgb4 (Neil Horman) [691929]

[2.6.32-131.0.7.el6]
- [virt] x86: better fix for race between nmi injection and enabling nmi window (Aristeu Rozanski)
- [virt] x86: revert 'fix race between nmi injection and enabling nmi window' (Aristeu ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.0.15.el6", rls:"OracleLinux6"))) {
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
