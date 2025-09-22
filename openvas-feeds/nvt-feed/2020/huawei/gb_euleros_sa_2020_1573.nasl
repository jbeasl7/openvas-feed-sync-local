# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1573");
  script_cve_id("CVE-2017-10664", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-15038", "CVE-2017-17381", "CVE-2017-5579", "CVE-2017-5856", "CVE-2017-6505", "CVE-2017-7718", "CVE-2017-8086", "CVE-2017-9310", "CVE-2017-9503", "CVE-2018-11806", "CVE-2018-15746", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18954", "CVE-2018-20815", "CVE-2018-7858", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-12247", "CVE-2019-13164", "CVE-2019-20175", "CVE-2019-9824");
  script_tag(name:"creation_date", value:"2020-04-30 12:14:08 +0000 (Thu, 30 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 15:41:33 +0000 (Mon, 03 Jun 2019)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2020-1573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1573");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1573");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2020-1573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The ohci_service_ed_list function in hw/usb/hcd-ohci.c in QEMU (aka Quick Emulator) before 2.9.0 allows local guest OS users to cause a denial of service (infinite loop) via vectors involving the number of link endpoint list descriptors, a different vulnerability than CVE-2017-9330.(CVE-2017-6505)

** DISPUTED ** QEMU 3.0.0 has an Integer Overflow because the qga/commands*.c files do not check the length of the argument list or the number of environment variables. NOTE: This has been disputed as not exploitable.(CVE-2019-12247)

** DISPUTED ** An issue was discovered in ide_dma_cb() in hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest system can crash the QEMU process in the host system via a special SCSI_IOCTL_SEND_COMMAND. It hits an assertion that implies that the size of successful DMA transfers there must be a multiple of 512 (the size of a sector). NOTE: a member of the QEMU security team disputes the significance of this issue because a 'privileged guest user has many ways to cause similar DoS effect, without triggering this assert.'(CVE-2019-20175)

Race condition in the v9fs_xattrwalk function in hw/9pfs/9p.c in QEMU (aka Quick Emulator) allows local guest OS users to obtain sensitive information from host heap memory via vectors related to reading extended attributes.(cve-2017-15038)

Memory leak in the megasas_handle_dcmd function in hw/scsi/megasas.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption) via MegaRAID Firmware Interface (MFI) commands with the sglist size set to a value over 2 Gb.(cve-2017-5856)

QEMU (aka Quick Emulator), when built with the e1000e NIC emulation support, allows local guest OS privileged users to cause a denial of service (infinite loop) via vectors related to setting the initial receive / transmit descriptor head (TDH/RDH) outside the allocated descriptor buffer.(cve-2017-9310)

QEMU (aka Quick Emulator), when built with MegaRAID SAS 8708EM2 Host Bus Adapter emulation support, allows local guest OS privileged users to cause a denial of service (NULL pointer dereference and QEMU process crash) via vectors involving megasas command processing.(cve-2017-9503)

The dhcp_decode function in slirp/bootp.c in QEMU (aka Quick Emulator) allows local guest OS users to cause a denial of service (out-of-bounds read and QEMU process crash) via a crafted DHCP options string.(CVE-2017-11434)

Memory leak in the v9fs_list_xattr function in hw/9pfs/9p-xattr.c in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (memory consumption) via vectors involving the orig_value variable.(CVE-2017-8086)

m_cat in slirp/mbuf.c in Qemu has a heap-based buffer overflow via incoming fragmented datagrams.(CVE-2018-11806)

In QEMU 3.1.0, load_device_tree in device_tree.c calls the deprecated load_image function, which has a buffer overflow ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~2.8.1~30.115", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.115", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.115", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.115", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
