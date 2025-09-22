# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856726");
  script_cve_id("CVE-2020-13956");
  script_tag(name:"creation_date", value:"2024-11-21 05:00:28 +0000 (Thu, 21 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-04 22:39:49 +0000 (Fri, 04 Dec 2020)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4036-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244036-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177488");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019823.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpcomponents-client, httpcomponents-core' package(s) announced via the SUSE-SU-2024:4036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for httpcomponents-client, httpcomponents-core fixes the following issues:

httpcomponents-client:
 - Update to version 4.5.14
 * HTTPCLIENT-2206: Corrected resource de-allocation by fluent
 response objects.
 * HTTPCLIENT-2174: URIBuilder to return a new empty list instead
 of unmodifiable Collections#emptyList.
 * Don't retry requests in case of NoRouteToHostException.
 * HTTPCLIENT-2144: RequestBuilder fails to correctly copy charset
 of requests with form url-encoded body.
 * PR #269: 4.5.x use array fill and more.
 + Use Arrays.fill().
 + Remove redundant modifiers.
 + Use Collections.addAll() and Collection.addAll() APIs instead of loops.
 + Remove redundant returns.
 + No need to explicitly declare an array when calling a vararg method.
 + Remote extra semicolons (,).
 + Use a 'L' instead of 'l' to make long literals more readable.
 * PublicSuffixListParser.parseByType(Reader) allocates but does
 not use a 256 char StringBuilder.
 * Incorrect handling of malformed authority component by
 URIUtils#extractHost (bsc#1177488, CVE-2020-13956).
 * Avoid updating Content-Length header in a 304 response.
 * Bug fix: BasicExpiresHandler is annotated as immutable but is
 not (#239)
 * HTTPCLIENT-2076: Fixed NPE in LaxExpiresHandler.

httpcomponents-core:
 - Upgraded to version 4.4.14
 * PR #231: 4.4.x Use better map apis and more.
 + Remove redundant modifiers.
 + Use Collections.addAll() API instead of loops.
 + Remove redundant returns.
 + No need to explicitly declare an array when calling a vararg method.
 + Remote extra semicolons (,).
 * Bug fix: Non-blocking TLSv1.3 connections can end up in an
 infinite event spin when closed concurrently by the local and
 the remote endpoints.
 * HTTPCORE-647: Non-blocking connection terminated due to
 'java.io.IOException: Broken pipe' can enter an infinite loop
 flushing buffered output data.
 * PR #201, HTTPCORE-634: Fix race condition in AbstractConnPool
 that can cause internal state corruption when persistent
 connections are manually removed from the pool.");

  script_tag(name:"affected", value:"'httpcomponents-client, httpcomponents-core' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client", rpm:"httpcomponents-client~4.5.14~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client-cache", rpm:"httpcomponents-client-cache~4.5.14~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client-javadoc", rpm:"httpcomponents-client-javadoc~4.5.14~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-core", rpm:"httpcomponents-core~4.4.14~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-core-javadoc", rpm:"httpcomponents-core-javadoc~4.4.14~150200.3.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client", rpm:"httpcomponents-client~4.5.14~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client-cache", rpm:"httpcomponents-client-cache~4.5.14~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-client-javadoc", rpm:"httpcomponents-client-javadoc~4.5.14~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-core", rpm:"httpcomponents-core~4.4.14~150200.3.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpcomponents-core-javadoc", rpm:"httpcomponents-core-javadoc~4.4.14~150200.3.9.1", rls:"openSUSELeap15.6"))) {
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
