# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1350");
  script_cve_id("CVE-2025-58767", "CVE-2025-61594");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-24 14:57:18 +0000 (Tue, 24 Feb 2026)");

  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2026-1350)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1350");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1350");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2026-1350 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"URI is a module providing classes to handle Uniform Resource Identifiers. In versions prior to 0.12.5, 0.13.3, and 1.0.4, a bypass exists for the fix to CVE-2025-27221 that can expose user credentials. When using the `+` operator to combine URIs, sensitive information like passwords from the original URI can be leaked, violating RFC3986 and making applications vulnerable to credential exposure. Versions 0.12.5, 0.13.3, and 1.0.4 fix the issue.(CVE-2025-61594)

REXML is an XML toolkit for Ruby. The REXML gems from 3.3.3 to 3.4.1 has a DoS vulnerability when parsing XML containing multiple XML declarations. If you need to parse untrusted XMLs, you may be impacted to these vulnerabilities. The REXML gem 3.4.2 or later include the patches to fix these vulnerabilities.(CVE-2025-58767)");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.5.8~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-help", rpm:"ruby-help~2.5.8~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.5.8~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~1.3.4~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-did_you_mean", rpm:"rubygem-did_you_mean~1.2.0~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.4.6~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~2.1.0~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-openssl", rpm:"rubygem-openssl~2.1.2~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~3.0.2~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~6.0.1.1~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~2.7.6~112.h23.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
