# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1647");
  script_cve_id("CVE-2015-5239", "CVE-2015-5278", "CVE-2015-5745", "CVE-2016-9602", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-6505", "CVE-2017-9330", "CVE-2018-12617", "CVE-2018-19364", "CVE-2018-19489", "CVE-2020-7039", "CVE-2020-8608");
  script_tag(name:"creation_date", value:"2020-06-16 05:48:04 +0000 (Tue, 16 Jun 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-04 13:51:55 +0000 (Mon, 04 Jun 2018)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-1647)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1647");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1647");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2020-1647 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer overflow in later code.(CVE-2020-8608)

Integer overflow in the VNC display driver in QEMU before 2.1.0 allows attachers to cause a denial of service (process crash) via a CLIENT_CUT_TEXT message, which triggers an infinite loop.(CVE-2015-5239)

The ne2000_receive function in hw
et
e2000.c in QEMU before 2.4.0.1 allows attackers to cause a denial of service (infinite loop and instance crash) or possibly execute arbitrary code via vectors related to receiving packets.(CVE-2015-5278)

Buffer overflow in the send_control_msg function in hw/char/virtio-serial-bus.c in QEMU before 2.4.0 allows guest users to cause a denial of service (QEMU process crash) via a crafted virtio control message.(CVE-2015-5745)

tcp_emu in tcp_subr.c in libslirp 4.1.0, as used in QEMU 4.2.0, mismanages memory, as demonstrated by IRC DCC commands in EMU_IRC. This can cause a heap-based buffer overflow or other out-of-bounds access which can lead to a DoS or potential execute arbitrary code.(CVE-2020-7039)

Qemu before version 2.9 is vulnerable to an improper link following when built with the VirtFS. A privileged user inside guest could use this flaw to access host file system beyond the shared folder and potentially escalating their privileges on a host.(CVE-2016-9602)

The ohci_service_ed_list function in hw/usb/hcd-ohci.c in QEMU (aka Quick Emulator) before 2.9.0 allows local guest OS users to cause a denial of service (infinite loop) via vectors involving the number of link endpoint list descriptors, a different vulnerability than CVE-2017-9330.(CVE-2017-6505)

qmp_guest_file_read in qga/commands-posix.c and qga/commands-win32.c in qemu-ga (aka QEMU Guest Agent) in QEMU 2.12.50 has an integer overflow causing a g_malloc0() call to trigger a segmentation fault when trying to allocate a large memory chunk. The vulnerability can be exploited by sending a crafted QMP command (including guest-file-read with a large count value) to the agent via the listening socket.(CVE-2018-12617)

Memory leak in hw/audio/ac97.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption and QEMU process crash) via a large number of device unplug operations.(CVE-2017-5525)

Memory leak in hw/audio/es1370.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption and QEMU process crash) via a large number of device unplug operations.(CVE-2017-5526)

QEMU (aka Quick Emulator) before 2.9.0, when built with the USB OHCI Emulation support, allows local guest OS users to cause a denial of service (infinite loop) by leveraging an incorrect return value, a different vulnerability than CVE-2017-6505.(CVE-2017-9330)

v9fs_wstat in hw/9pfs/9p.c in QEMU allows guest OS users to cause a denial of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~156.5.h31", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~156.5.h31", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~156.5.h31", rls:"EULEROS-2.0SP2"))) {
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
