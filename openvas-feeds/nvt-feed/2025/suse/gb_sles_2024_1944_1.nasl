# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1944.1");
  script_cve_id("CVE-2023-42843", "CVE-2023-42950", "CVE-2023-42956", "CVE-2024-23252", "CVE-2024-23254", "CVE-2024-23263", "CVE-2024-23280", "CVE-2024-23284", "CVE-2024-27834");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-08 22:48:38 +0000 (Mon, 08 Apr 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1944-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241944-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225071");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035528.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2024:1944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

- Update to version 2.44.2 (bsc#1225071):
- CVE-2024-23252: Fixed a vulnerability where processed web content may lead to a denial-of-service. (bsc#1222010)
- CVE-2024-23254: Fixed a vulnerability where a malicious website may exfiltrate audio data cross-origin. (bsc#1222010)
- CVE-2024-23263: Fixed a vulnerability where processed maliciously crafted web content may prevent Content Security Policy from being enforced. (bsc#1222010)
- CVE-2024-23280: Fixed a vulnerability where a maliciously crafted webpage may be able to fingerprint the user. (bsc#1222010)
- CVE-2024-23284: Fixed a vulnerability where processed maliciously crafted web content may prevent Content Security Policy from being enforced. (bsc#1222010)
- CVE-2023-42950: Fixed a vulnerability where processed maliciously crafted web content may lead to arbitrary code execution. (bsc#1222010)
- CVE-2023-42956: Fixed a vulnerability where processed web content may lead to a denial-of-service. (bsc#1222010)
- CVE-2023-42843: Fixed a vulnerability where visiting a malicious website may lead to address bar spoofing. (bsc#1222010)
- CVE-2024-27834: Fixed a vulnerability where an attacker with arbitrary read and write capability may be able to bypass Pointer Authentication. (bsc#1225071)");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-4.0-lang", rpm:"WebKitGTK-4.0-lang~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"WebKitGTK-6.0-lang", rpm:"WebKitGTK-6.0-lang~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-6_0-1", rpm:"libjavascriptcoregtk-6_0-1~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkitgtk-6_0-4", rpm:"libwebkitgtk-6_0-4~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-soup2-devel", rpm:"webkit2gtk3-soup2-devel~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkitgtk-6_0-injected-bundles", rpm:"webkitgtk-6_0-injected-bundles~2.44.2~150600.12.3.1", rls:"SLES15.0SP6"))) {
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
