# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1396");
  script_cve_id("CVE-2025-58098", "CVE-2025-65082", "CVE-2025-66200");
  script_tag(name:"creation_date", value:"2026-03-16 05:12:13 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2026-1396)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1396");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1396");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'httpd' package(s) announced via the EulerOS-SA-2026-1396 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled and mod_cgid (but not mod_cgi) passes the shell-escaped query string to #exec cmd='...' directives.

This issue affects Apache HTTP Server before 2.4.66.

Users are recommended to upgrade to version 2.4.66, which fixes the issue.(CVE-2025-58098)

Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache HTTP Server through environment variables set via the Apache configuration unexpectedly superseding variables calculated by the server for CGI programs.

This issue affects Apache HTTP Server from 2.4.0 through 2.4.65.

Users are recommended to upgrade to version 2.4.66 which fixes the issue.(CVE-2025-65082)

mod_userdir+suexec bypass via AllowOverride FileInfo vulnerability in Apache HTTP Server. Users with access to use the RequestHeader directive in htaccess can cause some CGI scripts to run under an unexpected userid.

This issue affects Apache HTTP Server: from 2.4.7 through 2.4.65.

Users are recommended to upgrade to version 2.4.66, which fixes the issue.(CVE-2025-66200)");

  script_tag(name:"affected", value:"'httpd' package(s) on Huawei EulerOS V2.0SP12.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.51~12.h21.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-filesystem", rpm:"httpd-filesystem~2.4.51~12.h21.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.51~12.h21.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.51~12.h21.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
