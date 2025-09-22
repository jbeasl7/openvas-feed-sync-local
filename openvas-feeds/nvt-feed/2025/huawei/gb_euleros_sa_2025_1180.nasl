# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1180");
  script_cve_id("CVE-2023-26112");
  script_tag(name:"creation_date", value:"2025-02-10 09:04:52 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-11T05:38:07+0000");
  script_tag(name:"last_modification", value:"2025-02-11 05:38:07 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 13:57:52 +0000 (Mon, 10 Apr 2023)");

  script_name("Huawei EulerOS: Security Advisory for python-configobj (EulerOS-SA-2025-1180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1180");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1180");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python-configobj' package(s) announced via the EulerOS-SA-2025-1180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"All versions of the package configobj are vulnerable to Regular Expression Denial of Service (ReDoS) via the validate function, using (.+?)\((.*)\).**Note:** This is only exploitable in the case of a developer, putting the offending value in a server side configuration file.(CVE-2023-26112)");

  script_tag(name:"affected", value:"'python-configobj' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"python3-configobj", rpm:"python3-configobj~5.0.6~18.h1.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
