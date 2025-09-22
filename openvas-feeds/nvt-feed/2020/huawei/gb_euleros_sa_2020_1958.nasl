# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1958");
  script_cve_id("CVE-2019-19377", "CVE-2019-19462", "CVE-2019-20806", "CVE-2019-20810", "CVE-2019-20811", "CVE-2019-20812", "CVE-2019-9445", "CVE-2020-0009", "CVE-2020-0305", "CVE-2020-0543", "CVE-2020-10711", "CVE-2020-10732", "CVE-2020-10751", "CVE-2020-10757", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-10769", "CVE-2020-10781", "CVE-2020-10942", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12465", "CVE-2020-12652", "CVE-2020-12653", "CVE-2020-12654", "CVE-2020-12655", "CVE-2020-12659", "CVE-2020-12770", "CVE-2020-12771", "CVE-2020-12826", "CVE-2020-12888", "CVE-2020-13143", "CVE-2020-13974", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-16166", "CVE-2020-25211", "CVE-2020-25220", "CVE-2020-25221");
  script_tag(name:"creation_date", value:"2020-09-08 08:07:05 +0000 (Tue, 08 Sep 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-15 17:30:37 +0000 (Tue, 15 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1958");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1958");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2020-1958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Android kernel in F2FS driver there is a possible out of bounds read due to a missing bounds check. This could lead to local information disclosure with system execution privileges needed. User interaction is not needed for exploitation.(CVE-2019-9445)

In calc_vm_may_flags of ashmem.c, there is a possible arbitrary write to shared memory due to a permissions bypass. This could lead to local escalation of privilege by corrupting memory shared between processes, with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android kernel Android ID: A-142938932(CVE-2020-0009)

A new domain bypass transient execution attack known as Special Register Buffer Data Sampling (SRBDS) has been found. This flaw allows data values from special internal registers to be leaked by an attacker able to execute code on any core of the CPU. An unprivileged, local attacker can use this flaw to infer values returned by affected instructions known to be commonly used during cryptographic operations that rely on uniqueness, secrecy, or both.(CVE-2020-0543)

A flaw was found in the Linux kernel's implementation of the BTRFS file system. A local attacker, with the ability to mount a file system, can create a use-after-free memory fault after the file system has been unmounted. This may lead to memory corruption or privilege escalation.(CVE-2019-19377)

A NULL pointer dereference flaw may occur in the Linux kernel's relay_open in kernel/relay.c. if the alloc_percpu() function is not validated in time of failure and used as a valid address for access. An attacker could use this flaw to cause a denial of service.(CVE-2019-19462)

A NULL pointer dereference flaw was found in tw5864_handle_frame function in drivers/media/pci/tw5864/tw5864-video.c in the TW5864 Series Video media driver. The pointer 'vb' is assigned, but not validated before its use, and can lead to a denial of service. This flaw allows a local attacker with special user or root privileges to crash the system or leak internal kernel information.(CVE-2019-20806)

go7007_snd_init in drivers/media/usb/go7007/snd-go7007.c in the Linux kernel before 5.6 does not call snd_card_free for a failure path, which causes a memory leak, aka CID-9453264ef586.(CVE-2019-20810)

An issue was discovered in the Linux kernel before 5.0.6. In rx_queue_add_kobject() and netdev_queue_add_kobject() in net/core
et-sysfs.c, a reference count is mishandled, aka CID-a3e23f719f5c.(CVE-2019-20811)

A flaw was found in the way the af_packet functionality in the Linux kernel handled the retirement timer setting for TPACKET_v3 when getting settings from the underlying network device errors out. This flaw allows a local user who can open the af_packet domain socket and who can hit the error path, to use this vulnerability to starve the system.(CVE-2019-20812)

A NULL pointer dereference flaw was ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h820", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
