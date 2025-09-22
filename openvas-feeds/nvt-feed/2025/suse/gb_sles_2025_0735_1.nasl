# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0735.1");
  script_cve_id("CVE-2024-27856", "CVE-2024-54479", "CVE-2024-54502", "CVE-2024-54505", "CVE-2024-54508", "CVE-2024-54534", "CVE-2024-54543", "CVE-2024-54658", "CVE-2025-24143", "CVE-2025-24150", "CVE-2025-24158", "CVE-2025-24162");
  script_tag(name:"creation_date", value:"2025-03-03 04:08:07 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-13 17:42:04 +0000 (Fri, 13 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0735-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0735-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250735-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236946");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020451.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:0735-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.46.6 (bsc#1236946, bsc#1234851):

- CVE-2025-24143: A maliciously crafted webpage may be able to fingerprint the user.
- CVE-2025-24150: Copying a URL from Web Inspector may lead to command injection.
- CVE-2025-24158: Processing web content may lead to a denial-of-service.
- CVE-2025-24162: Processing maliciously crafted web content may lead to an unexpected process crash.
- CVE-2024-54479: Processing maliciously crafted web content may lead to an unexpected process crash.
- CVE-2024-54502: Processing maliciously crafted web content may lead to an unexpected process crash.
- CVE-2024-54505: Processing maliciously crafted web content may lead to memory corruption.
- CVE-2024-54508: Processing maliciously crafted web content may lead to an unexpected process crash.
- CVE-2024-54543: Processing maliciously crafted web content may lead to memory corruption.

Already fixed in previous releases:

- CVE-2024-27856: Processing a file may lead to unexpected app termination or arbitrary code execution.
- CVE-2024-54534: Processing maliciously crafted web content may lead to memory corruption.
- CVE-2024-54658: Processing web content may lead to a denial-of-service.");

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

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.46.6~150200.133.1", rls:"SLES15.0SP3"))) {
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
