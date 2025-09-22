# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02992.1");
  script_cve_id("CVE-2025-48989");
  script_tag(name:"creation_date", value:"2025-08-29 04:06:49 +0000 (Fri, 29 Aug 2025)");
  script_version("2025-08-29T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-08-29 05:38:41 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02992-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02992-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502992-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243895");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041365.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat11' package(s) announced via the SUSE-SU-2025:02992-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tomcat11 fixes the following issues:

Updated to Tomcat 11.0.10
- CVE-2025-48989: Fixed 'MadeYouReset' DoS in HTTP/2 due to client triggered stream reset (bsc#1243895)

Other fixes:
 * Catalina
 + Fix: Fix bloom filter population for archive indexing when using a
 packed WAR containing one or more JAR files. (markt)
 * Coyote
 + Fix: 69748: Add missing call to set keep-alive timeout when using
 HTTP/1.1 following an async request, which was present for AJP.
 (remm/markt)
 + Fix: 69762: Fix possible overflow during HPACK decoding of integers.
 Note that the maximum permitted value of an HPACK decoded integer is
 Integer.MAX_VALUE. (markt)
 + Fix: Update the HTTP/2 overhead documentation - particularly the code
 comments - to reflect the deprecation of the PRIORITY frame and
 clarify that a stream reset always triggers an overhead increase.
 (markt)
 * Cluster
 + Update: Add enableStatistics configuration attribute for the
 DeltaManager, defaulting to true. (remm)
 * WebSocket
 + Fix: Align the WebSocket extension handling for WebSocket client
 connections with WebSocket server connections. The WebSocket client
 now only includes an extension requested by an endpoint in the
 opening handshake if the WebSocket client supports that extension.
 (markt)
 * Web applications
 + Fix: Manager and Host Manager. Provide the Manager and Host Manager
 web applications with a dedicated favicon file rather than using the
 one from the ROOT web application which might not be present or may
 represent something entirely different. Pull requests #876 and #878
 by Simon Arame.
 * Other
 + Update: Update Checkstyle to 10.26.1. (markt)
 + Add: Improvements to French translations. (remm)
 + Add: Improvements to Japanese translations by tak7iji. (markt)");

  script_tag(name:"affected", value:"'tomcat11' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"tomcat11", rpm:"tomcat11~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-admin-webapps", rpm:"tomcat11-admin-webapps~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-doc", rpm:"tomcat11-doc~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-docs-webapp", rpm:"tomcat11-docs-webapp~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-el-6_0-api", rpm:"tomcat11-el-6_0-api~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-embed", rpm:"tomcat11-embed~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-jsp-4_0-api", rpm:"tomcat11-jsp-4_0-api~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-jsvc", rpm:"tomcat11-jsvc~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-lib", rpm:"tomcat11-lib~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-servlet-6_1-api", rpm:"tomcat11-servlet-6_1-api~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat11-webapps", rpm:"tomcat11-webapps~11.0.10~150600.13.9.1", rls:"openSUSELeap15.6"))) {
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
