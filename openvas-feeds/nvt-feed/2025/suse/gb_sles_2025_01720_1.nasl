# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.01720.1");
  script_cve_id("CVE-2023-42875", "CVE-2023-42970", "CVE-2025-24223", "CVE-2025-31204", "CVE-2025-31205", "CVE-2025-31206", "CVE-2025-31215", "CVE-2025-31257");
  script_tag(name:"creation_date", value:"2025-05-30 04:09:15 +0000 (Fri, 30 May 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:01720-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01720-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501720-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243596");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039367.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2025:01720-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.48.2.

Security issues fixed:

- CVE-2025-31205: lack of checks may lead to cross-origin data exfiltration through a malicious website (bsc#1243282).
- CVE-2025-31204: improper memory handling when processing certain web content may lead to memory corruption
 (bsc#1243286).
- CVE-2025-31206: type confusion issue when processing certain web content may lead to an unexpected crash
 (bsc#1243288).
- CVE-2025-31215: lack of checks when processing certain web content may lead to an unexpected crash (bsc#1243289).
- CVE-2025-31257: improper memory handling when processing certain web content may lead to an unexpected crash
 (bsc#1243596).
- CVE-2025-24223: improper memory handling when processing certain web content may lead to memory corruption
 (bsc#1243424).

Other changes and issues fixed:

- Enable CSS overscroll behavior by default.
- Change threaded rendering implementation to use Skia API instead of WebCore display list that is not thread safe.
- Fix rendering when device scale factor change comes before the web view geometry update.
- Fix network process crash on exit.
- Fix the build with ENABLE_RESOURCE_USAGE=OFF.
- Fix several crashes and rendering issues.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.48.2~4.38.1", rls:"SLES12.0SP5"))) {
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
