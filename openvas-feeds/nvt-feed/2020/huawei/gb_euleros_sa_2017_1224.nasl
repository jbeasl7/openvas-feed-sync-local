# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2017.1224");
  script_cve_id("CVE-2016-4020", "CVE-2017-10664", "CVE-2017-2633", "CVE-2017-5898");
  script_tag(name:"creation_date", value:"2020-01-23 10:59:49 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:55+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:55 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-04 15:50:26 +0000 (Fri, 04 Aug 2017)");

  script_name("Huawei EulerOS: Security Advisory for qemu-kvm (EulerOS-SA-2017-1224)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2017-1224");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2017-1224");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu-kvm' package(s) announced via the EulerOS-SA-2017-1224 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds memory access issue was found in Quick Emulator (QEMU) in the VNC display driver. This flaw could occur while refreshing the VNC display surface area in the 'vnc_refresh_server_surface'. A user inside a guest could use this flaw to crash the QEMU process. (CVE-2017-2633)

An integer overflow flaw was found in Quick Emulator (QEMU) in the CCID Card device support. The flaw could occur while passing messages via command/response packets to and from the host. A privileged user inside a guest could use this flaw to crash the QEMU process. (CVE-2017-5898)

An information exposure flaw was found in Quick Emulator (QEMU) in Task Priority Register (TPR) optimizations for 32-bit Windows guests. The flaw could occur while accessing TPR. A privileged user inside a guest could use this issue to read portions of the host memory. (CVE-2016-4020)

Quick Emulator (QEMU) built with the Network Block Device (NBD) Server support is vulnerable to a crash via a SIGPIPE signal. The crash can occur if a client aborts a connection due to any failure during negotiation or read operation. A remote user/process could use this flaw to crash the qemu-nbd server resulting in a DoS. (CVE-2017-10664)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~141.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~141.h1", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~141.h1", rls:"EULEROS-2.0SP2"))) {
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
