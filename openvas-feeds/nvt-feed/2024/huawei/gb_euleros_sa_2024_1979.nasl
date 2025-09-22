# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1979");
  script_cve_id("CVE-2023-1393", "CVE-2023-5367", "CVE-2023-5380", "CVE-2024-31080", "CVE-2024-31081", "CVE-2024-31082", "CVE-2024-31083");
  script_tag(name:"creation_date", value:"2024-07-16 08:46:04 +0000 (Tue, 16 Jul 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-05 12:15:37 +0000 (Fri, 05 Apr 2024)");

  script_name("Huawei EulerOS: Security Advisory for xorg-x11-server (EulerOS-SA-2024-1979)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1979");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1979");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'xorg-x11-server' package(s) announced via the EulerOS-SA-2024-1979 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in X.Org Server Overlay Window. A Use-After-Free may lead to local privilege escalation. If a client explicitly destroys the compositor overlay window (aka COW), the Xserver would leave a dangling pointer to that window in the CompScreen structure, which will trigger a use-after-free later.(CVE-2023-1393)

A out-of-bounds write flaw was found in the xorg-x11-server. This issue occurs due to an incorrect calculation of a buffer offset when copying data stored in the heap in the XIChangeDeviceProperty function in Xi/xiproperty.c and in RRChangeOutputProperty function in randr/rrproperty.c, allowing for possible escalation of privileges or denial of service.(CVE-2023-5367)

A use-after-free flaw was found in the xorg-x11-server. An X server crash may occur in a very specific and legacy configuration (a multi-screen setup with multiple protocol screens, also known as Zaphod mode) if the pointer is warped from within a window on one screen to the root window of the other screen and if the original window is destroyed followed by another window being destroyed.(CVE-2023-5380)

A heap-based buffer over-read vulnerability was found in the X.org server's ProcAppleDRICreatePixmap() function. This issue occurs when byte-swapped length values are used in replies, potentially leading to memory leakage and segmentation faults, particularly when triggered by a client with a different endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory values and then transmit them back to the client until encountering an unmapped page, resulting in a crash. Despite the attacker's inability to control the specific memory copied into the replies, the small length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds reads.(CVE-2024-31082)

A heap-based buffer over-read vulnerability was found in the X.org server's ProcXIPassiveGrabDevice() function. This issue occurs when byte-swapped length values are used in replies, potentially leading to memory leakage and segmentation faults, particularly when triggered by a client with a different endianness. This vulnerability could be exploited by an attacker to cause the X server to read heap memory values and then transmit them back to the client until encountering an unmapped page, resulting in a crash. Despite the attacker's inability to control the specific memory copied into the replies, the small length values typically stored in a 32-bit integer can result in significant attempted out-of-bounds reads.(CVE-2024-31081)

A use-after-free vulnerability was found in the ProcRenderAddGlyphs() function of Xorg servers. This issue occurs when AllocateGlyph() is called to store new glyphs sent by the client to the X server, potentially resulting in multiple entries pointing to the same non-refcounted glyphs. Consequently, ProcRenderAddGlyphs() may free a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-help", rpm:"xorg-x11-server-help~1.20.6~5.h14.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
