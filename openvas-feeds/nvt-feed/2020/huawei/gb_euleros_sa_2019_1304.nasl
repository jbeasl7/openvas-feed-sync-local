# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1304");
  script_cve_id("CVE-2017-13168", "CVE-2018-10877", "CVE-2018-16884", "CVE-2018-19985", "CVE-2018-9422", "CVE-2019-11190", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6133");
  script_tag(name:"creation_date", value:"2020-01-23 11:38:27 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 17:21:29 +0000 (Wed, 30 Jan 2019)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2019-1304)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1304");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1304");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2019-1304 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An elevation of privilege vulnerability in the kernel scsi driver. Product: Android. Versions: Android kernel. Android ID A-65023233.(CVE-2017-13168)

Non-optimized code for key handling of shared futexes was found in the Linux kernel in the form of unbounded contention time due to the page lock for real-time users. Before the fix, the page lock was an unnecessarily heavy lock for the futex path that protected too much. After the fix, the page lock is only required in a specific corner case.(CVE-2018-9422)

A flaw in the load_elf_binary() function in the Linux kernel allows a local attacker to leak the base address of .text and stack sections for setuid binaries and bypass ASLR because install_exec_creds() is called too late in this function.(CVE-2019-11190)

A flaw was found in the Linux kernel ext4 filesystem. An out-of-bound access is possible in the ext4_ext_drop_refs() function when operating on a crafted ext4 filesystem image.(CVE-2018-10877)

A vulnerability was found in polkit. When authentication is performed by a non-root user to perform an administrative task, the authentication is temporarily cached in such a way that a local attacker could impersonate the authorized process, thus gaining access to elevated privileges.(CVE-2019-6133)

A flaw was found in the Linux kernel in the function hso_probe() which reads if_num value from the USB device (as an u8) and uses it without a length check to index an array, resulting in an OOB memory read in hso_probe() or hso_get_config_data(). An attacker with a forged USB device and physical access to a system (needed to connect such a device) can cause a system crash and a denial of service.(CVE-2018-19985)

A flaw was found in the Linux kernel's implementation of logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack in the l2cap_parse_conf_rsp and l2cap_parse_conf_req functions. An attacker with physical access within the range of standard Bluetooth transmission can create a specially crafted packet. The response to this specially crafted packet can contain part of the kernel stack which can be used in a further attack.(CVE-2019-3460)

A flaw was found in the Linux kernels implementation of Logical link control and adaptation protocol (L2CAP), part of the Bluetooth stack. An attacker with physical access within the range of standard Bluetooth transmission can create a specially crafted packet. The response to this specially crafted packet can contain part of the kernel stack which can be used in a further attack.(CVE-2019-3459)

A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out.(CVE-2018-16884)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.14.0.1.h137.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
