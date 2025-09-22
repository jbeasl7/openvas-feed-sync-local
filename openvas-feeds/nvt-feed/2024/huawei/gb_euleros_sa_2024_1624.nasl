# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1624");
  script_cve_id("CVE-2023-6683", "CVE-2023-6693");
  script_tag(name:"creation_date", value:"2024-05-15 13:13:00 +0000 (Wed, 15 May 2024)");
  script_version("2024-05-16T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-12 19:15:11 +0000 (Fri, 12 Jan 2024)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2024-1624)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.11\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1624");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1624");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2024-1624 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack based buffer overflow was found in the virtio-net device of QEMU. This issue occurs when flushing TX in the virtio_net_flush_tx function if guest features VIRTIO_NET_F_HASH_REPORT, VIRTIO_F_VERSION_1 and VIRTIO_NET_F_MRG_RXBUF are enabled. This could allow a malicious user to overwrite local variables allocated on the stack. Specifically, the `out_sg` variable could be used to read a part of process memory and send it to the wire, causing an information leak.(CVE-2023-6683)

A flaw was found in the QEMU built-in VNC server while processing ClientCutText messages. The qemu_clipboard_request() function can be reached before vnc_server_cut_text_caps() was called and had the chance to initialize the clipboard peer, leading to a NULL pointer dereference. This could allow a malicious authenticated VNC client to crash QEMU and trigger a denial of service.(CVE-2023-6693)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.11.1.");

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

if(release == "EULEROSVIRT-2.11.1") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~6.2.0~464", rls:"EULEROSVIRT-2.11.1"))) {
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
