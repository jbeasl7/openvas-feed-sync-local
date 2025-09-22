# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1492");
  script_cve_id("CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2550", "CVE-2016-2847", "CVE-2016-3070", "CVE-2016-3134", "CVE-2016-3135", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3841", "CVE-2016-3955", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4565");
  script_tag(name:"creation_date", value:"2020-01-23 11:55:47 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-05 17:21:17 +0000 (Tue, 05 Jul 2016)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1492)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1492");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1492");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1492 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The snd_timer_interrupt function in sound/core/timer.c in the Linux kernel before 4.4.1 does not properly maintain a certain linked list, which allows local users to cause a denial of service (race condition and system crash) via a crafted ioctl call.(CVE-2016-2545)

sound/core/timer.c in the Linux kernel before 4.4.1 uses an incorrect type of mutex, which allows local users to cause a denial of service (race condition, use-after-free, and system crash) via a crafted ioctl call.(CVE-2016-2546)

sound/core/timer.c in the Linux kernel before 4.4.1 employs a locking approach that does not consider slave timer instances, which allows local users to cause a denial of service (race condition, use-after-free, and system crash) via a crafted ioctl call.(CVE-2016-2547)

sound/core/timer.c in the Linux kernel before 4.4.1 retains certain linked lists after a close or stop action, which allows local users to cause a denial of service (system crash) via a crafted ioctl call, related to the (1) snd_timer_close and (2) _snd_timer_stop functions.(CVE-2016-2548)

sound/core/hrtimer.c in the Linux kernel before 4.4.1 does not prevent recursive callback access, which allows local users to cause a denial of service (deadlock) via a crafted ioctl call.(CVE-2016-2549)

A resource-exhaustion vulnerability was found in the kernel, where an unprivileged process could allocate and accumulate far more file descriptors than the process' limit. A local, unauthenticated user could exploit this flaw by sending file descriptors over a Unix socket and then closing them to keep the process' fd count low, thereby creating kernel-memory or file-descriptors exhaustion (denial of service).(CVE-2016-2550)

It is possible for a single process to cause an OOM condition by filling large pipes with data that are never read. A typical process filling 4096 pipes with 1 MB of data will use 4 GB of memory and there can be multiple such processes, up to a per-user-limit.(CVE-2016-2847)

A security flaw was found in the Linux kernel that an attempt to move page mapped by AIO ring buffer to the other node triggers NULL pointer dereference at trace_writeback_dirty_page(), because aio_fs_backing_dev_info.dev is 0.(CVE-2016-3070)

A security flaw was found in the Linux kernel in the mark_source_chains() function in 'net/ipv4/netfilter/ip_tables.c'. It is possible for a user-supplied 'ipt_entry' structure to have a large 'next_offset' field. This field is not bounds checked prior to writing to a counter value at the supplied offset.(CVE-2016-3134)

An integer overflow vulnerability was found in the Linux kernel in xt_alloc_table_info, which on 32-bit systems can lead to small structure allocation and a copy_from_user based heap corruption.(CVE-2016-3135)

The mct_u232_msr_to_state function in drivers/usb/serial/mct_u232.c in the Linux kernel before 4.5.1 allows physically proximate attackers to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.1.6_42", rls:"EULEROSVIRT-3.0.1.0"))) {
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
