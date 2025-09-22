# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1678");
  script_cve_id("CVE-2025-27219", "CVE-2025-27220", "CVE-2025-27221");
  script_tag(name:"creation_date", value:"2025-06-12 10:55:30 +0000 (Thu, 12 Jun 2025)");
  script_version("2025-06-13T05:40:07+0000");
  script_tag(name:"last_modification", value:"2025-06-13 05:40:07 +0000 (Fri, 13 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-05 14:58:14 +0000 (Wed, 05 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2025-1678)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1678");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1678");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2025-1678 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the CGI gem before 0.4.2 for Ruby, a Regular Expression Denial of Service (ReDoS) vulnerability exists in the Util#escapeElement method.(CVE-2025-27220)

In the URI gem before 1.0.3 for Ruby, the URI handling methods (URI.join, URI#merge, URI#+) have an inadvertent leakage of authentication credentials because userinfo is retained even after changing the host.(CVE-2025-27221)

In the CGI gem before 0.4.2 for Ruby, the CGI::Cookie.parse method in the CGI library contains a potential Denial of Service (DoS) vulnerability. The method does not impose any limit on the length of the raw cookie value it processes. This oversight can lead to excessive resource consumption when parsing extremely large cookies.(CVE-2025-27219)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~3.0.3~122.h16.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-help", rpm:"ruby-help~3.0.3~122.h16.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~3.0.3~122.h16.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
