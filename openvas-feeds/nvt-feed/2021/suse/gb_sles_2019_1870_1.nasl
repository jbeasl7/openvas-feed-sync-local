# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1870.1");
  script_cve_id("CVE-2018-20836", "CVE-2018-5390", "CVE-2018-7191", "CVE-2019-11478", "CVE-2019-11487", "CVE-2019-12456", "CVE-2019-12614", "CVE-2019-12818");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:59:15 +0000 (Tue, 07 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1870-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1870-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191870-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139751");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005724.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1870-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2018-5390 aka 'SegmentSmack': A remote attacker even with relatively low bandwidth could have caused lots of CPU usage
 by triggering the worst case scenario during IP and/or TCP fragment reassembly (bsc#1102340)
- CVE-2018-7191: In the tun subsystem in the Linux kernel, dev_get_valid_name was not called before register_netdevice. This allowed local users to cause a denial of service (NULL pointer dereference and panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. (bnc#1135603)
- CVE-2018-20836: A race condition in smp_task_timedout() and smp_task_done() in drivers/scsi/libsas/sas_expander.c, could have lead to a use-after-free. (bnc#1134395)
- CVE-2019-12614: An unchecked kstrdup might have allowed an attacker to cause denial of service (a NULL pointer dereference and system crash). (bnc#1137194)
- CVE-2019-12818: The nfc_llcp_build_tlv function in net/nfc/llcp_commands.c may have returned NULL. If the caller did not check for this, it would trigger a NULL pointer dereference. This would cause denial of service. (bnc#1138293)
- CVE-2019-12456: An issue in the MPT3COMMAND case in _ctl_ioctl_main() allowed local users to cause a denial of service or possibly have unspecified other impact by changing the value of ioc_number between two kernel reads of that value, aka a 'double fetch' vulnerability. (bsc#1136922)
- CVE-2019-11487: An attacker could have triggered use-after-free via page reference count overflow on slow filesystems with at least of 140 GiB of RAM available. (bnc#1133190)

The following non-security bugs were fixed:

- fuse: Don't access pipe->buffers without pipe_lock() (Prerequisity for CVE-2019-11487, bsc#1133190).
- fuse: call pipe_buf_release() under pipe lock (Prerequisity for CVE-2019-11487, bsc#1133190).
- mm: /proc/pid/maps: Check permissions when opening proc pid maps (bsc#1130159).
- pipe: add pipe_buf_get() helper (Prerequisity for CVE-2019-11487, bsc#1133190).
- tcp: refine memory limit test in tcp_fragment() after CVE-2019-11478 fix (bsc#1139751).
- x86/bugs: do not default to IBRS even on SKL (bsc#1112824).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.74~60.64.118.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.74~60.64.118.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_118-default", rpm:"kgraft-patch-3_12_74-60_64_118-default~1~2.3.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_74-60_64_118-xen", rpm:"kgraft-patch-3_12_74-60_64_118-xen~1~2.3.1", rls:"SLES12.0SP1"))) {
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
