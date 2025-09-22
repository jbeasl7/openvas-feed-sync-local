# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3261.1");
  script_cve_id("CVE-2017-15706", "CVE-2018-11784", "CVE-2018-1304", "CVE-2018-1305", "CVE-2018-1336", "CVE-2018-8014", "CVE-2018-8034");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 17:44:20 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3261-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3261-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183261-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110850");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004749.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-7.0-doc/changelog.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2018:3261-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat fixes the following issues:

Version update to 7.0.90:

- Another bugfix release, for full details see:
 [link moved to references]

Security issues fixed:

- CVE-2018-11784: When the default servlet in Apache Tomcat returned
 a redirect to a directory (e.g. redirecting to '/foo/' when the user
 requested '/foo') a specially crafted URL could be used to cause the
 redirect to be generated to any URI of the attackers choice. (bsc#1110850)
- CVE-2017-15706: As part of the fix for bug 61201, the documentation
 for Apache Tomcat included an updated description of the search algorithm
 used by the CGI Servlet to identify which script to execute. The update
 was not correct. As a result, some scripts may have failed to execute as
 expected and other scripts may have been executed unexpectedly. Note that
 the behaviour of the CGI servlet has remained unchanged in this regard.
 It is only the documentation of the behaviour that was wrong and has
 been corrected.(bsc#1078677)
- CVE-2018-1304: The URL pattern of \'\' (the empty string) which exactly
 maps to the context root was not correctly handled in Apache Tomcat
 when used as part of a security constraint definition. This caused the
 constraint to be ignored. It was, therefore, possible for unauthorised
 users to gain access to web application resources that should have
 been protected. Only security constraints with a URL pattern of the
 empty string were affected. (bsc#1082480)
- CVE-2018-1305: Security constraints defined by annotations of Servlets
 in Apache Tomcat were only applied once a Servlet had been loaded. Because
 security constraints defined in this way apply to the URL pattern and
 any URLs below that point, it was possible - depending on the order
 Servlets were loaded - for some security constraints not to be applied.
 This could have exposed resources to users who were not authorised to
 access them.(bsc#1082481)
- CVE-2018-1336: An improper handing of overflow in the UTF-8 decoder with
 supplementary characters can lead to an infinite loop in the decoder causing
 a Denial of Service. (bsc#1102400)
- CVE-2018-8014: Fixed default settings for the CORS filter, which were
 insecure and enabled 'supportsCredentials' for all origins. (bsc#1093697)
- CVE-2018-8034: Fixed the host name verification when using TLS with the
 WebSocket client, which was not enabled by default. (bsc#1102379)");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Linux Enterprise Server 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2_2-api", rpm:"tomcat-el-2_2-api~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_2-api", rpm:"tomcat-jsp-2_2-api~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3_0-api", rpm:"tomcat-servlet-3_0-api~7.0.90~7.23.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.90~7.23.1", rls:"SLES12.0"))) {
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
