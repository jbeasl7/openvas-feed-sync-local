# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1014");
  script_cve_id("CVE-2024-47220", "CVE-2024-49761");
  script_tag(name:"creation_date", value:"2025-01-14 04:31:02 +0000 (Tue, 14 Jan 2025)");
  script_version("2025-01-14T05:37:03+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:03 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:41:46 +0000 (Tue, 05 Nov 2024)");

  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2025-1014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1014");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1014");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2025-1014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the WEBrick toolkit through 1.8.1 for Ruby. It allows HTTP request smuggling by providing both a Content-Length header and a Transfer-Encoding header, e.g., 'GET /admin HTTP/1.1\r\n' inside of a 'POST /user HTTP/1.1\r\n' request. NOTE: the supplier's position is 'Webrick should not be used in production.'(CVE-2024-47220)

REXML is an XML toolkit for Ruby. The REXML gem before 3.3.9 has a ReDoS vulnerability when it parses an XML that has many digits between &# and x..., in a hex numeric character reference (&#x...,). This does not happen with Ruby 3.2 or later. Ruby 3.1 is the only affected maintained Ruby. The REXML gem 3.3.9 or later include the patch to fix the vulnerability.(CVE-2024-49761)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.5.8~112.h18.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-help", rpm:"ruby-help~2.5.8~112.h18.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.5.8~112.h18.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
