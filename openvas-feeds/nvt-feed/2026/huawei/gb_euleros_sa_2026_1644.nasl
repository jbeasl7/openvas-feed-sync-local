# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1644");
  script_cve_id("CVE-2025-12464");
  script_tag(name:"creation_date", value:"2026-03-19 04:58:29 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-31 22:15:32 +0000 (Fri, 31 Oct 2025)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2026-1644)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1644");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1644");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2026-1644 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A stack-based buffer overflow was found in the QEMU e1000 network device. The code for padding short frames was dropped from individual network devices and moved to the net core code. The issue stems from the device's receive code still being able to process a short frame in loopback mode. This could lead to a buffer overrun in the e1000_receive_iov() function via the loopback code path. A malicious guest user could use this vulnerability to crash the QEMU process on the host, resulting in a denial of service.(CVE-2025-12464)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.13.0.");

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

if(release == "EULEROSVIRT-2.13.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~6.2.0.oe2203sp3~2.13.0.6.623", rls:"EULEROSVIRT-2.13.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-gpu-specs", rpm:"qemu-gpu-specs~6.2.0.oe2203sp3~2.13.0.6.623", rls:"EULEROSVIRT-2.13.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~6.2.0.oe2203sp3~2.13.0.6.623", rls:"EULEROSVIRT-2.13.0"))) {
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
