# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1057");
  script_cve_id("CVE-2017-13711", "CVE-2017-16845", "CVE-2017-18030", "CVE-2017-7493", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2018-11806", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-20815", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-20175", "CVE-2020-14364");
  script_tag(name:"creation_date", value:"2021-01-08 21:56:56 +0000 (Fri, 08 Jan 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-10 17:42:19 +0000 (Thu, 10 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2021-1057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.2\.6");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1057");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1057");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2021-1057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Quick Emulator (Qemu) built with the VirtFS, host directory sharing via Plan 9 File System(9pfs) support, is vulnerable to an improper access control issue. It could occur while accessing virtfs metadata files in mapped-file security mode. A guest user could use this flaw to escalate their privileges inside guest.(CVE-2017-7493)

qemu-bridge-helper.c in QEMU 4.0.0 does not ensure that a network interface name (obtained from bridge.conf or a --br=bridge option) is limited to the IFNAMSIZ size, which can lead to an ACL bypass.(CVE-2019-13164)

Qemu has a Buffer Overflow in pcnet_receive in hw/net/pcnet.c because an incorrect integer data type is used.(CVE-2018-17962)

Buffer overflow in the 'megasas_mmio_write' function in Qemu 2.9.0 allows remote attackers to have unspecified impact via unknown vectors.(CVE-2017-8380)

qemu_deliver_packet_iov in net/net.c in Qemu accepts packet sizes greater than INT_MAX, which allows attackers to cause a denial of service or possibly have unspecified other impact.(CVE-2018-17963)

In QEMU 3.1.0, load_device_tree in device_tree.c calls the deprecated load_image function, which has a buffer overflow risk.(CVE-2018-20815)

interface_release_resource in hw/display/qxl.c in QEMU 4.0.0 has a NULL pointer dereference.(CVE-2019-12155)

An issue was discovered in ide_dma_cb() in hw/ide/core.c in QEMU 2.4.0 through 4.2.0. The guest system can crash the QEMU process in the host system via a special SCSI_IOCTL_SEND_COMMAND. It hits an assertion that implies that the size of successful DMA transfers there must be a multiple of 512 (the size of a sector). NOTE: a member of the QEMU security team disputes the significance of this issue because a 'privileged guest user has many ways to cause similar DoS effect, without triggering this assert.'(CVE-2019-20175)

Use-after-free vulnerability in the sofree function in slirp/socket.c in QEMU (aka Quick Emulator) allows attackers to cause a denial of service (QEMU instance crash) by leveraging failure to properly clear ifq_so from pending packets.(CVE-2017-13711)

Qemu has a Buffer Overflow in rtl8139_do_receive in hw/net/rtl8139.c because an incorrect integer data type is used.(CVE-2018-17958)

ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer overflow via a large packet because it mishandles a case involving the first fragment.(CVE-2019-14378)

m_cat in slirp/mbuf.c in Qemu has a heap-based buffer overflow via incoming fragmented datagrams.(CVE-2018-11806)

Memory leak in the audio/audio.c in QEMU (aka Quick Emulator) allows remote attackers to cause a denial of service (memory consumption) by repeatedly starting and stopping audio capture.(CVE-2017-8309)

Memory leak in the keyboard input event handlers support in QEMU (aka Quick Emulator) allows local guest OS privileged users to cause a denial of service (host memory consumption) by rapidly generating large keyboard ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization 3.0.2.6.");

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

if(release == "EULEROSVIRT-3.0.2.6") {

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~2.8.1~30.086", rls:"EULEROSVIRT-3.0.2.6"))) {
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
