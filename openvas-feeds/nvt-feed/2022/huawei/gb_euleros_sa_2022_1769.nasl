# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1769");
  script_cve_id("CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4192", "CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0729", "CVE-2022-0943", "CVE-2022-1154");
  script_tag(name:"creation_date", value:"2022-05-25 04:17:28 +0000 (Wed, 25 May 2022)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 20:36:59 +0000 (Thu, 11 Aug 2022)");

  script_name("Huawei EulerOS: Security Advisory for vim (EulerOS-SA-2022-1769)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1769");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-1769");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'vim' package(s) announced via the EulerOS-SA-2022-1769 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"vim is vulnerable to Heap-based Buffer Overflow(CVE-2022-0213)

Access of Memory Location Before Start of Buffer in GitHub repository vim/vim prior to 8.2.(CVE-2022-0351)

Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2.(CVE-2022-0359)

Use of Out-of-range Pointer Offset in GitHub repository vim/vim prior to 8.2.4440.(CVE-2022-0729)

Heap-based Buffer Overflow occurs in vim in GitHub repository vim/vim prior to 8.2.4563.(CVE-2022-0943)

Use after free in utf_ptr2char in GitHub repository vim/vim prior to 8.2.4646.(CVE-2022-1154)

A flaw was found in vim. A possible heap-based buffer overflow vulnerability allows an attacker to input a specially crafted file, leading to a crash or code execution. The highest threat from this vulnerability is system availability.(CVE-2021-4019)

vim is vulnerable to Use After Free(CVE-2021-4069)

A flaw was found in vim. A possible heap-based buffer overflow allows an attacker to input a specially crafted file, leading to a crash or code execution. The highest threat from this vulnerability is confidentiality, integrity, and system availability.(CVE-2021-3984)

vim is vulnerable to Use After Free(CVE-2021-4192)

vim is vulnerable to Out-of-bounds Read(CVE-2021-4193)");

  script_tag(name:"affected", value:"'vim' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.4.160~2.h20", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.4.160~2.h20", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.4.160~2.h20", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-filesystem", rpm:"vim-filesystem~7.4.160~2.h20", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.4.160~2.h20", rls:"EULEROS-2.0SP3"))) {
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
