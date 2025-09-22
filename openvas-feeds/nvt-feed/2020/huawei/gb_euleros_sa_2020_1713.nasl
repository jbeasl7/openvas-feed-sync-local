# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1713");
  script_cve_id("CVE-2014-8181", "CVE-2017-5967", "CVE-2019-18675", "CVE-2019-19768", "CVE-2019-20636", "CVE-2020-10741", "CVE-2020-10942", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12464", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12770", "CVE-2020-12826", "CVE-2020-13143", "CVE-2020-8647", "CVE-2020-8649", "CVE-2020-8992", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2020-07-03 06:18:13 +0000 (Fri, 03 Jul 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-08 15:10:49 +0000 (Fri, 08 May 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1713");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1713");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2020-1713 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-buffer).(CVE-2019-19768)

The Linux kernel through 5.3.13 has a start_offset+size Integer Overflow in cpia2_remap_buffer in drivers/media/usb/cpia2/cpia2_core.c because cpia2 has its own mmap implementation. This allows local users (with /dev/video0 access) to obtain read and write permissions on kernel physical pages, which can possibly result in a privilege escalation.(CVE-2019-18675)

An issue was discovered in the Linux kernel through 5.5.6. set_fdc in drivers/block/floppy.c leads to a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it, aka CID-2e90ca68b0d2.(CVE-2020-9383)

There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region function in drivers/video/console/vgacon.c.(CVE-2020-8649)

There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in drivers/tty/vt/vt.c.(CVE-2020-8647)

The time subsystem in the Linux kernel, when CONFIG_TIMER_STATS is enabled, allows local users to discover real PID values (as distinguished from PID values inside a PID namespace) by reading the /proc/timer_list file, related to the print_timer function in kernel/time/timer_list.c and the __timer_stats_timer_set_start_info function in kernel/time/timer.c.(CVE-2017-5967)

The kernel in Red Hat Enterprise Linux 7 and MRG-2 does not clear garbage data for SG_IO buffer, which may leaking sensitive information to userspace.(CVE-2014-8181)

ext4_protect_reserved_inode in fs/ext4/block_validity.c in the Linux kernel through 5.5.3 allows attackers to cause a denial of service (soft lockup) via a crafted journal size.(CVE-2020-8992)

** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2020-12826. Reason: This candidate is a duplicate of CVE-2020-12826. Notes: All CVE users should reference CVE-2020-12826 instead of this candidate. All references and descriptions in this candidate have been removed to prevent accidental usage.(CVE-2020-10741)

A signal access-control issue was discovered in the Linux kernel before 5.6.5, aka CID-7395ea4e65c2. Because exec_id in include/linux/sched.h is only 32 bits, an integer overflow can interfere with a do_notify_parent protection mechanism. A child process can send an arbitrary signal to a parent process in a different security domain. Exploitation limitations include the amount of elapsed time before an integer overflow occurs, and the lack of scenarios where signals to a parent process present a substantial operational threat.(CVE-2020-12826)

gadget_dev_desc_UDC_store in drivers/usb/gadget/configfs.c in the Linux kernel through 5.6.13 relies on kstrdup without considering the possibility of an internal ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.6.0.");

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

if(release == "EULEROSVIRT-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_111", rls:"EULEROSVIRT-3.0.6.0"))) {
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
