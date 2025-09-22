# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1660.1");
  script_cve_id("CVE-2016-0762", "CVE-2016-3092", "CVE-2016-5018", "CVE-2016-5388", "CVE-2016-6794", "CVE-2016-6796", "CVE-2016-6797", "CVE-2016-6816", "CVE-2016-8735", "CVE-2016-8745", "CVE-2017-5647", "CVE-2017-5648");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:35 +0000 (Thu, 27 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1660-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1660-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171660-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1033448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988489");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-June/002971.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/tomcat-7.0-doc/changelog.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the SUSE-SU-2017:1660-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomcat was updated to version 7.0.78, fixing various bugs and security issues.

For full details see [link moved to references]

Security issues fixed:

- CVE-2016-0762: A realm timing attack in tomcat was fixed which could disclose existence of users (bsc#1007854)
- CVE-2016-3092: Usage of vulnerable FileUpload package could have resulted in denial of service (bsc#986359)
- CVE-2016-5018: A security manager bypass via a Tomcat utility method that was accessible to web applications was fixed. (bsc#1007855)
- CVE-2016-5388: Setting HTTP_PROXY environment variable via Proxy header (bsc#988489)
- CVE-2016-6794: A tomcat system property disclosure was fixed. (bsc#1007857)
- CVE-2016-6796: A tomcat security manager bypass via manipulation of the configuration parameters for the JSP Servlet. (bsc#1007858)
- CVE-2016-6797: A tomcat unrestricted access to global resources via ResourceLinkFactory was fixed. (bsc#1007853)
- CVE-2016-6816: A HTTP Request smuggling vulnerability due to permitting invalid character in HTTP requests was fixed. (bsc#1011812)
- CVE-2016-8735: A Remote code execution vulnerability in JmxRemoteLifecycleListener was fixed (bsc#1011805)
- CVE-2016-8745: A Tomcat Information Disclosure in the error handling of send file code for the NIO HTTP connector was fixed. (bsc#1015119)
- CVE-2017-5647: A tomcat information disclosure in pipelined request processing was fixed. (bsc#1033448)
- CVE-2017-5648: A tomcat information disclosure due to using incorrect facade objects was fixed (bsc#1033447)");

  script_tag(name:"affected", value:"'tomcat' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-2_2-api", rpm:"tomcat-el-2_2-api~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-javadoc", rpm:"tomcat-javadoc~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2_2-api", rpm:"tomcat-jsp-2_2-api~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-3_0-api", rpm:"tomcat-servlet-3_0-api~7.0.78~7.13.4", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~7.0.78~7.13.4", rls:"SLES12.0"))) {
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
