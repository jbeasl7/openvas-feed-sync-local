# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.1756");
  script_cve_id("CVE-2021-33641", "CVE-2021-33642");
  script_tag(name:"creation_date", value:"2023-05-08 04:14:25 +0000 (Mon, 08 May 2023)");
  script_version("2024-02-05T14:36:57+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:57 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 19:53:49 +0000 (Tue, 26 Sep 2023)");

  script_name("Huawei EulerOS: Security Advisory for byacc (EulerOS-SA-2023-1756)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-1756");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2023-1756");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'byacc' package(s) announced via the EulerOS-SA-2023-1756 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Berkeley Yacc is an LALR(1) parser generator. Berkeley Yacc has been made as compatible as possible with AT&T Yacc. Berkeley Yacc can accept any input specification that conforms to the AT&T Yacc documentation. Specifications that take advantage of undocumented features of AT&T Yacc will probably be rejected.(CVE-2021-33641)

Berkeley Yacc is an LALR(1) parser generator. Berkeley Yacc has been made as compatible as possible with AT&T Yacc. Berkeley Yacc can accept any input specification that conforms to the AT&T Yacc documentation. Specifications that take advantage of undocumented features of AT&T Yacc will probably be rejected.(CVE-2021-33642)");

  script_tag(name:"affected", value:"'byacc' package(s) on Huawei EulerOS V2.0SP11.");

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

  if(!isnull(res = isrpmvuln(pkg:"byacc", rpm:"byacc~2.0.20210808~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"byacc-help", rpm:"byacc-help~2.0.20210808~1.h2.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
