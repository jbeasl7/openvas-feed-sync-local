# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1622");
  script_cve_id("CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595");
  script_tag(name:"creation_date", value:"2022-05-05 11:46:32 +0000 (Thu, 05 May 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 17:06:49 +0000 (Wed, 23 Jun 2021)");

  script_name("Huawei EulerOS: Security Advisory for qemu (EulerOS-SA-2022-1622)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1622");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1622");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'qemu' package(s) announced via the EulerOS-SA-2022-1622 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the bootp_input() function and could occur while processing a udp packet that is smaller than the size of the 'bootp_t' structure. A malicious guest could use this flaw to leak 10 bytes of uninitialized heap memory from the host. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3592)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp6_input() function and could occur while processing a udp packet that is smaller than the size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3593)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the udp_input() function and could occur while processing a udp packet that is smaller than the size of the 'udphdr' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3594)

An invalid pointer initialization issue was found in the SLiRP networking implementation of QEMU. The flaw exists in the tftp_input() function and could occur while processing a udp packet that is smaller than the size of the 'tftp_t' structure. This issue may lead to out-of-bounds read access or indirect host memory disclosure to the guest. The highest threat from this vulnerability is to data confidentiality. This flaw affects libslirp versions prior to 4.6.0.(CVE-2021-3595)");

  script_tag(name:"affected", value:"'qemu' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.1.0~2.9.1.2.357", rls:"EULEROSVIRT-2.9.0"))) {
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
