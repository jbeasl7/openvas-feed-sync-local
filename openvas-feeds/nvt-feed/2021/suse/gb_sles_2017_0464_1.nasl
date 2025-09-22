# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0464.1");
  script_cve_id("CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7913", "CVE-2016-7914", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 19:11:13 +0000 (Thu, 09 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0464-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0464-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170464-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/972993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999101");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0464-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.69 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2015-8962: Double free vulnerability in the sg_common_write function in drivers/scsi/sg.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (memory corruption and system crash) by detaching a device during an SG_IO ioctl call (bnc#1010501).
- CVE-2015-8963: Race condition in kernel/events/core.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) by leveraging incorrect handling of an swevent data structure during a CPU unplug operation (bnc#1010502).
- CVE-2015-8964: The tty_set_termios_ldisc function in drivers/tty/tty_ldisc.c in the Linux kernel allowed local users to obtain sensitive information from kernel memory by reading a tty data structure (bnc#1010507).
- CVE-2016-10088: The sg implementation in the Linux kernel did not properly restrict write operations in situations where the KERNEL_DS option is set, which allowed local users to read or write to arbitrary kernel memory locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg device, related to block/bsg.c and drivers/scsi/sg.c. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-9576 (bnc#1017710).
- CVE-2016-7910: Use-after-free vulnerability in the disk_seqf_stop function in block/genhd.c in the Linux kernel allowed local users to gain privileges by leveraging the execution of a certain stop operation even if the corresponding start operation had failed (bnc#1010716).
- CVE-2016-7911: Race condition in the get_task_ioprio function in block/ioprio.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) via a crafted ioprio_get system call (bnc#1010711).
- CVE-2016-7913: The xc2028_set_config function in drivers/media/tuners/tuner-xc2028.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (use-after-free) via vectors involving omission of the firmware name from a certain data structure (bnc#1010478).
- CVE-2016-7914: The assoc_array_insert_into_terminal_node function in lib/assoc_array.c in the Linux kernel did not check whether a slot is a leaf, which allowed local users to obtain sensitive information from kernel memory or cause a denial of service (invalid pointer dereference and out-of-bounds read) via an application that uses associative-array data structures, as demonstrated by the keyutils test suite (bnc#1010475).
- CVE-2016-8399: An elevation of privilege vulnerability in the kernel networking subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Moderate because it first requires compromising a privileged process and current compiler ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.69~60.64.29.1", rls:"SLES12.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.69~60.64.29.1", rls:"SLES12.0SP1"))) {
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
