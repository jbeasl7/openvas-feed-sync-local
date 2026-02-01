# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20102.1");
  script_cve_id("CVE-2023-43000", "CVE-2025-13502", "CVE-2025-13947", "CVE-2025-14174", "CVE-2025-43272", "CVE-2025-43342", "CVE-2025-43343", "CVE-2025-43356", "CVE-2025-43368", "CVE-2025-43392", "CVE-2025-43419", "CVE-2025-43421", "CVE-2025-43425", "CVE-2025-43427", "CVE-2025-43429", "CVE-2025-43430", "CVE-2025-43431", "CVE-2025-43432", "CVE-2025-43434", "CVE-2025-43440", "CVE-2025-43443", "CVE-2025-43458", "CVE-2025-43480", "CVE-2025-43501", "CVE-2025-43529", "CVE-2025-43531", "CVE-2025-43535", "CVE-2025-43536", "CVE-2025-43541", "CVE-2025-66287");
  script_tag(name:"creation_date", value:"2026-01-26 08:39:16 +0000 (Mon, 26 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:15:56 +0000 (Thu, 04 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20102-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620102-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255497");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023882.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2026:20102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.50.4.

Security issues fixed:

- CVE-2025-13502: processing of maliciously crafted payloads by the GLib remote inspector server may lead to a
 UIProcess crash due to an out-of-bounds read and an integer underflow (bsc#1254208).
- CVE-2025-13947: use of the file drag-and-drop mechanism may lead to remote information disclosure due to a lack of
 verification of the origins of drag operations (bsc#1254473).
- CVE-2025-14174: processing maliciously crafted web content may lead to memory corruption due to improper validation
 (bsc#1255497).
- CVE-2025-43272: processing maliciously crafted web content may lead to an unexpected process crash due to improper
 memory handling (bsc#1250439).
- CVE-2025-43342: processing maliciously crafted web content may lead to an unexpected process crash due to a
 correctness issue and missing checks (bsc#1250440).
- CVE-2025-43343: processing maliciously crafted web content may lead to an unexpected process crash due to improper
 memory handling (bsc#1251975).
- CVE-2025-43356: a website may be able to access sensor information without user consent due to improper cache handling
 (bsc#1250441).
- CVE-2025-43368: processing maliciously crafted web content may lead to an unexpected process crash due to a
 use-after-free issue (bsc#1250442).
- CVE-2025-43392: websites may exfiltrate image data cross-origin due to issues with cache handling (bsc#1254165).
- CVE-2025-43419: processing maliciously crafted web content may lead to memory corruption due to improper memory
 handling (bsc#1254166).
- CVE-2025-43421: processing maliciously crafted web content may lead to an unexpected process crash due to enabled
 array allocation sinking (bsc#1254167).
- CVE-2025-43425: processing maliciously crafted web content may lead to an unexpected process crash due to improper
 memory handling (bsc#1254168).
- CVE-2025-43427: processing maliciously crafted web content may lead to an unexpected process crash due to issues with
 state management (bsc#1254169).
- CVE-2025-43429: processing maliciously crafted web content may lead to an unexpected process crash due to a buffer
 overflow issue (bsc#1254174).
- CVE-2025-43430: processing maliciously crafted web content may lead to an unexpected process crash due to issues with
 state management (bsc#1254172).
- CVE-2025-43431: processing maliciously crafted web content may lead to memory corruption due to improper memory
 handling (bsc#1254170).
- CVE-2025-43432: processing maliciously crafted web content may lead to an unexpected process crash due to a
 use-after-free issue (bsc#1254171).
- CVE-2025-43434: processing maliciously crafted web content may lead to an unexpected process crash due to a
 use-after-free issue (bsc#1254179).
- CVE-2025-43440: processing maliciously crafted web content may lead to an unexpected process crash due to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.1-lang", rpm:"WebKitGTK-4.1-lang~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_1-0", rpm:"libjavascriptcoregtk-4_1-0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_1-0", rpm:"libwebkit2gtk-4_1-0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_1", rpm:"typelib-1_0-JavaScriptCore-4_1~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-6_0", rpm:"typelib-1_0-JavaScriptCore-6_0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit-6_0", rpm:"typelib-1_0-WebKit-6_0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_1", rpm:"typelib-1_0-WebKit2-4_1~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_1", rpm:"typelib-1_0-WebKit2WebExtension-4_1~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKitWebProcessExtension-6_0", rpm:"typelib-1_0-WebKitWebProcessExtension-6_0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-4.1", rpm:"webkit-jsc-4.1~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit-jsc-6.0", rpm:"webkit-jsc-6.0~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_1-injected-bundles", rpm:"webkit2gtk-4_1-injected-bundles~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk4-minibrowser", rpm:"webkit2gtk4-minibrowser~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.50.4~160000.1.1", rls:"SLES16.0.0"))) {
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
