# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122051");
  script_cve_id("CVE-2011-1162", "CVE-2011-1577", "CVE-2011-2494", "CVE-2011-2699", "CVE-2011-3188", "CVE-2011-3191", "CVE-2011-3353", "CVE-2011-3593", "CVE-2011-4326");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:15 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-2033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-2033");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-2033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, ofa-2.6.32-200.23.1.el5uek, ofa-2.6.32-200.23.1.el6uek' package(s) announced via the ELSA-2011-2033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-200.23.1.el6uek]
- net: Remove atmclip.h to prevent break kabi check.
- KConfig: add CONFIG_UEK5=n to ol6/config-generic

[2.6.32-200.22.1.el6uek]
- ipv6: make fragment identifications less predictable (Joe Jin) {CVE-2011-2699}
- vlan: fix panic when handling priority tagged frames (Joe Jin) {CVE-2011-3593}
- ipv6: udp: fix the wrong headroom check (Maxim Uvarov) {CVE-2011-4326}
- b43: allocate receive buffers big enough for max frame len + offset (Maxim Uvarov) {CVE-2011-3359}
- fuse: check size of FUSE_NOTIFY_INVAL_ENTRY message (Maxim Uvarov) {CVE-2011-3353}
- cifs: fix possible memory corruption in CIFSFindNext (Maxim Uvarov) {CVE-2011-3191}
- crypto: md5 - Add export support (Maxim Uvarov) {CVE-2011-2699}
- fs/partitions/efi.c: corrupted GUID partition tables can cause kernel oops (Maxim Uvarov) {CVE-2011-1577}
- block: use struct parsed_partitions *state universally in partition check code (Maxim Uvarov)
- net: Compute protocol sequence numbers and fragment IDs using MD5. (Maxim Uvarov) {CVE-2011-3188}
- crypto: Move md5_transform to lib/md5.c (Maxim Uvarov) {CVE-2011-3188}
- perf tools: do not look at ./config for configuration (Maxim Uvarov) {CVE-2011-2905}
- Make TASKSTATS require root access (Maxim Uvarov) {CVE-2011-2494}
- TPM: Zero buffer after copying to userspace (Maxim Uvarov) {CVE-2011-1162}
- TPM: Call tpm_transmit with correct size (Maxim Uvarov){CVE-2011-1161}
- fnic: fix panic while booting in fnic(Xiaowei Hu)
- Revert 'PCI hotplug: acpiphp: set current_state to D0 in register_slot' (Guru Anbalagane)
- xen: drop xen_sched_clock in favour of using plain wallclock time (Jeremy Fitzhardinge)

[2.6.32-200.21.1.el6uek]
- PCI: Set device power state to PCI_D0 for device without native PM support
 (Ajaykumar Hotchandani) [orabug 13033435]");

  script_tag(name:"affected", value:"'kernel-uek, ofa-2.6.32-200.23.1.el5uek, ofa-2.6.32-200.23.1.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~200.23.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.23.1.el5uek", rpm:"ofa-2.6.32-200.23.1.el5uek~1.5.1~4.0.53", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.23.1.el5uekdebug", rpm:"ofa-2.6.32-200.23.1.el5uekdebug~1.5.1~4.0.53", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~200.23.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.23.1.el6uek", rpm:"ofa-2.6.32-200.23.1.el6uek~1.5.1~4.0.47", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-200.23.1.el6uekdebug", rpm:"ofa-2.6.32-200.23.1.el6uekdebug~1.5.1~4.0.47", rls:"OracleLinux6"))) {
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
