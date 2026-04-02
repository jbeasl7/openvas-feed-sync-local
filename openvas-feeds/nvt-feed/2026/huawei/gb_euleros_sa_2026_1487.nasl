# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1487");
  script_cve_id("CVE-2024-42516", "CVE-2024-43204", "CVE-2024-47252", "CVE-2025-23048", "CVE-2025-49812", "CVE-2025-58098", "CVE-2025-65082", "CVE-2025-66200");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for httpd (EulerOS-SA-2026-1487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1487");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1487");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'httpd' package(s) announced via the EulerOS-SA-2026-1487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server 2.4.65 and earlier with Server Side Includes (SSI) enabled and mod_cgid (but not mod_cgi) passes the shell-escaped query string to #exec cmd='...' directives.This issue affects Apache HTTP Server before 2.4.66.Users are recommended to upgrade to version 2.4.66, which fixes the issue.(CVE-2025-58098)

Improper Neutralization of Escape, Meta, or Control Sequences vulnerability in Apache HTTP Server through environment variables set via the Apache configuration unexpectedly superseding variables calculated by the server for CGI programs.This issue affects Apache HTTP Server from 2.4.0 through 2.4.65.Users are recommended to upgrade to version 2.4.66 which fixes the issue.(CVE-2025-65082)

mod_userdir+suexec bypass via AllowOverride FileInfo vulnerability in Apache HTTP Server. Users with access to use the RequestHeader directive in htaccess can cause some CGI scripts to run under an unexpected userid.This issue affects Apache HTTP Server: from 2.4.7 through 2.4.65.Users are recommended to upgrade to version 2.4.66, which fixes the issue.(CVE-2025-66200)

HTTP response splitting in the core of Apache HTTP Server allows an attacker who can manipulate the Content-Type response headers of applications hosted or proxied by the server can split the HTTP response. This vulnerability was described as CVE-2023-38709 but the patch included in Apache HTTP Server 2.4.59 did not address the issue. Users are recommended to upgrade to version 2.4.64, which fixes this issue.(CVE-2024-42516)

In some mod_ssl configurations on Apache HTTP Server versions through to 2.4.63, an HTTP desynchronisation attack allows a man-in-the-middle attacker to hijack an HTTP session via a TLS upgrade.Only configurations using 'SSLEngine optional' to enable TLS upgrades are affected. Users are recommended to upgrade to version 2.4.64, which removes support for TLS upgrade.(CVE-2025-49812)

In some mod_ssl configurations on Apache HTTP Server 2.4.35 through to 2.4.63, an access control bypass by trusted clients is possible using TLS 1.3 session resumption.Configurations are affected when mod_ssl is configured for multiple virtual hosts, with each restricted to a different set of trusted client certificates (for example with a different SSLCACertificateFile/Path setting). In such a case, a client trusted to access one virtual host may be able to access another virtual host, if SSLStrictSNIVHostCheck is not enabled in either virtual host.(CVE-2025-23048)

Insufficient escaping of user-supplied data in mod_ssl in Apache HTTP Server 2.4.63 and earlier allows an untrusted SSL/TLS client to insert escape characters into log files in some configurations.In a logging configuration where CustomLog is used with '%{varname}x' or '%{varname}c' to log variables provided by mod_ssl such as SSL_TLS_SNI, no escaping is performed by either mod_log_config or mod_ssl and unsanitized data provided by the client ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'httpd' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

if(release == "EULEROSVIRT-2.12.0") {

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.4.51~12.h21.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-filesystem", rpm:"httpd-filesystem~2.4.51~12.h21.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.4.51~12.h21.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.4.51~12.h21.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
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
