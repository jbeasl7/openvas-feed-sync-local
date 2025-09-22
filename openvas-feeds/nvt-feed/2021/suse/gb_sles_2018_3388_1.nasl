# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3388.1");
  script_cve_id("CVE-2017-15706", "CVE-2018-11784", "CVE-2018-1304", "CVE-2018-1305", "CVE-2018-1336", "CVE-2018-8014", "CVE-2018-8034", "CVE-2018-8037");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 17:44:20 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3388-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183388-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110850");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004782.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2018:3388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat to version 8.0.53 fixes the following security issues:

- CVE-2018-11784: When the default servlet in Apache Tomcat returned
 a redirect to a directory (e.g. redirecting to '/foo/' when the user
 requested '/foo') a specially crafted URL could be used to cause the
 redirect to be generated to any URI of the attackers choice. (bsc#1110850)
- CVE-2018-1336: An improper handing of overflow in the UTF-8 decoder with
 supplementary characters could have lead to an infinite loop in the decoder
 causing a Denial of Service (bsc#1102400)
- CVE-2018-8034: The host name verification when using TLS with the WebSocket
 client was missing. It is now enabled by default (bsc#1102379)
- CVE-2018-8037: If an async request was completed by the application at the
 same time as the container triggered the async timeout, a race condition
 existed that could have resulted in a user seeing a response intended for a
 different user. An additional issue was present in the NIO and NIO2 connectors
 that did not correctly track the closure of the connection when an async
 request was completed by the application and timed out by the container at the
 same time. This could also have resulted in a user seeing a response intended
 for another user (bsc#1102410)
- CVE-2018-1305: Fixed late application of security constraints that can lead
 to resource exposure for unauthorised users (bsc#1082481).
- CVE-2018-1304: Fixed incorrect handling of empty string URL in security
 constraints that can lead to unitended exposure of resources (bsc#1082480).
- CVE-2017-15706: Fixed incorrect documentation of CGI Servlet search algorithm
 that may lead to misconfiguration (bsc#1078677).
- CVE-2018-8014: The defaults settings for the CORS filter were insecure and
 enable 'supportsCredentials' for all origins (bsc#1093697).");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3_0-api", rpm:"tomcat-el-3_0-api~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_3-api", rpm:"tomcat-jsp-2_3-api~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3_1-api", rpm:"tomcat-servlet-3_1-api~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~8.0.53~10.35.1", rls:"SLES12.0SP1"))) {
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
