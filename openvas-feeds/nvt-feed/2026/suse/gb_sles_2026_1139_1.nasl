# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.1139.1");
  script_cve_id("CVE-2023-42843", "CVE-2023-43010", "CVE-2024-54658", "CVE-2025-13502", "CVE-2025-31223", "CVE-2025-31277", "CVE-2025-43213", "CVE-2025-43214", "CVE-2025-43368", "CVE-2025-43419", "CVE-2025-43433", "CVE-2025-43434", "CVE-2025-43438", "CVE-2025-43440", "CVE-2025-43441", "CVE-2025-43443", "CVE-2025-43457", "CVE-2025-43511", "CVE-2025-46299", "CVE-2026-20608", "CVE-2026-20635", "CVE-2026-20636", "CVE-2026-20644", "CVE-2026-20652", "CVE-2026-20676");
  script_tag(name:"creation_date", value:"2026-04-01 04:59:17 +0000 (Wed, 01 Apr 2026)");
  script_version("2026-04-01T06:13:16+0000");
  script_tag(name:"last_modification", value:"2026-04-01 06:13:16 +0000 (Wed, 01 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-13 14:46:38 +0000 (Fri, 13 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:1139-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1139-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261139-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259950");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/025063.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2026:1139-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

Update to version 2.52.0:

- CVE-2023-43010: processing maliciously crafted web content may lead to memory corruption (bsc#1259950).
- CVE-2025-31223: processing maliciously crafted web content may lead to memory corruption (bsc#1259949).
- CVE-2025-31277: processing maliciously crafted web content may lead to memory corruption (bsc#1259948).
- CVE-2025-43213: processing maliciously crafted web content may lead to an unexpected crash (bsc#1259947).
- CVE-2025-43214: processing maliciously crafted web content may lead to an unexpected crash (bsc#1259946).
- CVE-2025-43433: processing maliciously crafted web content may lead to memory corruption (bsc#1259945).
- CVE-2025-43438: processing maliciously crafted web content may lead to an unexpected crash (bsc#1259944).
- CVE-2025-43441: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259943).
- CVE-2025-43457: processing maliciously crafted web content may lead to an unexpected crash (bsc#1259942).
- CVE-2025-43511: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259941).
- CVE-2025-46299: processing maliciously crafted web content may disclose internal states of an app (bsc#1259940).
- CVE-2026-20608: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259939).
- CVE-2026-20635: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259938).
- CVE-2026-20636: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259937).
- CVE-2026-20644: processing maliciously crafted web content may lead to an unexpected process crash (bsc#1259936).
- CVE-2026-20652: a remote attacker may be able to cause a denial-of-service (bsc#1259935).
- CVE-2026-20676: a website may be able to track users through web extensions (bsc#1259934).

Changelog:

 + Make scrolling with touch input smoother for small movements.
 + Fix estimated load progress of downloads when Content-Length
 value is wrong.
 + Ensure that 'scrollend' events are correctly emitted after
 scroll animations.
 + Fix several crashes and rendering issues.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.52.0~4.54.1", rls:"SLES12.0SP5"))) {
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
