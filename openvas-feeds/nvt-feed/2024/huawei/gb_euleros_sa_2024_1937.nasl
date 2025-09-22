# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1937");
  script_cve_id("CVE-2019-25162", "CVE-2021-46904", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46921", "CVE-2021-46928", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46960", "CVE-2021-46988", "CVE-2021-46999", "CVE-2021-47006", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47054", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47074", "CVE-2021-47076", "CVE-2021-47077", "CVE-2021-47078", "CVE-2021-47082", "CVE-2021-47101", "CVE-2021-47131", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47182", "CVE-2021-47185", "CVE-2021-47203", "CVE-2021-47342", "CVE-2022-48626", "CVE-2022-48627", "CVE-2022-48697", "CVE-2023-52458", "CVE-2023-52477", "CVE-2023-52486", "CVE-2023-52515", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52528", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52597", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-52646", "CVE-2024-1151", "CVE-2024-23307", "CVE-2024-24855", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26614", "CVE-2024-26640", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26686", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26828", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26872", "CVE-2024-26878", "CVE-2024-26882", "CVE-2024-26884", "CVE-2024-26894", "CVE-2024-26901", "CVE-2024-26915", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26973", "CVE-2024-26976", "CVE-2024-26982", "CVE-2024-26993", "CVE-2024-27008", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27019", "CVE-2024-27046", "CVE-2024-27059", "CVE-2024-27395", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-07-16 08:46:04 +0000 (Tue, 16 Jul 2024)");
  script_version("2025-01-15T05:38:11+0000");
  script_tag(name:"last_modification", value:"2025-01-15 05:38:11 +0000 (Wed, 15 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-14 14:27:22 +0000 (Tue, 14 Jan 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1937)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1937");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1937");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1937 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: KVM: s390: fix setting of fpc register kvm_arch_vcpu_ioctl_set_fpu() allows to set the floating point control (fpc) register of a guest cpu. The new value is tested for validity by temporarily loading it into the fpc register. This may lead to corruption of the fpc register of the host process: if an interrupt happens while the value is temporarily loaded into the fpc register, and within interrupt context floating point or vector registers are used, the current fp/vx registers are saved with save_fpu_regs() assuming they belong to user space and will be loaded into fp/vx registers when returning to user space. test_fp_ctl() restores the original user space / host process fpc register value, however it will be discarded, when returning to user space. In result the host process will incorrectly continue to run with the value that was supposed to be used for a guest cpu. Fix this by simply removing the test. There is another test right before the SIE context is entered which will handles invalid values. This results in a change of behaviour: invalid values will now be accepted instead of that the ioctl fails with -EINVAL. This seems to be acceptable, given that this interface is most likely not used anymore, and this is in addition the same behaviour implemented with the memory mapped interface (replace invalid values with zero) - see sync_regs() in kvm-s390.c.(CVE-2023-52597)

In the Linux kernel, the following vulnerability has been resolved: i2c: Fix a potential use after free Free the adap structure only after we are done using it. This patch just moves the put_device() down a bit to avoid the use after free. [wsa: added comment to the code, added Fixes tag](CVE-2019-25162)

In the Linux kernel, the following vulnerability has been resolved: net: hso: fix null-ptr-deref during tty device unregistration Multiple ttys try to claim the same the minor number causing a double unregistration of the same device. The first unregistration succeeds but the next one results in a null-ptr-deref. The get_free_serial_index() function returns an available minor number but doesn't assign it immediately. The assignment is done by the caller later. But before this assignment, calls to get_free_serial_index() would return the same minor number. Fix this by modifying get_free_serial_index to assign the minor number immediately after one is found to be and rename it to obtain_minor() to better reflect what it does. Similary, rename set_serial_by_index() to release_minor() and modify it to free up the minor number of the given hso_serial. Every obtain_minor() should have corresponding release_minor() call.(CVE-2021-46904)

In the Linux kernel, the following vulnerability has been resolved: HID: usbhid: fix info leak in hid_submit_ctrl In hid_submit_ctrl(), the way of calculating the report length doesn't take into account ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9.");

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

if(release == "EULEROS-2.0SP9") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2103.1.0.h1263.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2103.1.0.h1263.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2103.1.0.h1263.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2103.1.0.h1263.eulerosv2r9", rls:"EULEROS-2.0SP9"))) {
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
