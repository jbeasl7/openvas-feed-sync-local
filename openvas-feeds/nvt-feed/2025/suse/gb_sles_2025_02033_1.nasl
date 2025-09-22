# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02033.1");
  script_cve_id("CVE-2023-42875", "CVE-2023-42970", "CVE-2025-24223", "CVE-2025-31204", "CVE-2025-31205", "CVE-2025-31206", "CVE-2025-31215", "CVE-2025-31257");
  script_tag(name:"creation_date", value:"2025-06-23 04:17:35 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02033-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02033-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502033-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243596");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040413.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:02033-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.48.2:

- CVE-2025-24223: Processing maliciously crafted web content may lead to memory corruption (bsc#1243424).
- CVE-2025-31204: Processing maliciously crafted web content may lead to memory corruption (bsc#1243286).
- CVE-2025-31205: A malicious website may exfiltrate data cross-origin (bsc#1243282).
- CVE-2025-31206: Processing maliciously crafted web content may lead to an unexpected crash (bsc#1243288).
- CVE-2025-31215: Processing maliciously crafted web content may lead to an unexpected process crash (bsc#1243289).
- CVE-2025-31257: Improper memory handling when processing certain web content may lead to an unexpected crash (bsc#1243596).
- CVE-2023-42875: Improper memory handling may lead to arbitrary code execution when processing certain web content (bsc#1241158).
- CVE-2023-42970: Improper memory management may lead to use-after-free when processing certain web content (bsc#1241160).");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.48.2~150200.147.1", rls:"SLES15.0SP3"))) {
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
