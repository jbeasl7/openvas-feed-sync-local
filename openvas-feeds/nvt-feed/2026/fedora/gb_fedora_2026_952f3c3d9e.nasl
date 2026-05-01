# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.95210239931009101");
  script_cve_id("CVE-2026-5858", "CVE-2026-5859", "CVE-2026-5860", "CVE-2026-5861", "CVE-2026-5862", "CVE-2026-5863", "CVE-2026-5864", "CVE-2026-5865", "CVE-2026-5866", "CVE-2026-5867", "CVE-2026-5868", "CVE-2026-5869", "CVE-2026-5870", "CVE-2026-5871", "CVE-2026-5872", "CVE-2026-5873", "CVE-2026-5874", "CVE-2026-5875", "CVE-2026-5876", "CVE-2026-5877", "CVE-2026-5878", "CVE-2026-5879", "CVE-2026-5880", "CVE-2026-5881", "CVE-2026-5882", "CVE-2026-5883", "CVE-2026-5884", "CVE-2026-5885", "CVE-2026-5886", "CVE-2026-5887", "CVE-2026-5888", "CVE-2026-5889", "CVE-2026-5890", "CVE-2026-5891", "CVE-2026-5892", "CVE-2026-5893", "CVE-2026-5894", "CVE-2026-5895", "CVE-2026-5896", "CVE-2026-5897", "CVE-2026-5898", "CVE-2026-5899", "CVE-2026-5900", "CVE-2026-5901", "CVE-2026-5902", "CVE-2026-5903", "CVE-2026-5904", "CVE-2026-5905", "CVE-2026-5906", "CVE-2026-5907", "CVE-2026-5908", "CVE-2026-5909", "CVE-2026-5910", "CVE-2026-5911", "CVE-2026-5912", "CVE-2026-5913", "CVE-2026-5914", "CVE-2026-5915", "CVE-2026-5918", "CVE-2026-5919");
  script_tag(name:"creation_date", value:"2026-04-14 05:00:06 +0000 (Tue, 14 Apr 2026)");
  script_version("2026-04-14T06:16:47+0000");
  script_tag(name:"last_modification", value:"2026-04-14 06:16:47 +0000 (Tue, 14 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-952f3c3d9e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-952f3c3d9e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-952f3c3d9e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2457163");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2457164");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2026-952f3c3d9e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 147.0.7727.55

 * Critical CVE-2026-5858: Heap buffer overflow in WebML
 * Critical CVE-2026-5859: Integer overflow in WebML
 * High CVE-2026-5860: Use after free in WebRTC
 * High CVE-2026-5861: Use after free in V8
 * High CVE-2026-5862: Inappropriate implementation in V8
 * High CVE-2026-5863: Inappropriate implementation in V8
 * High CVE-2026-5864: Heap buffer overflow in WebAudio
 * High CVE-2026-5865: Type Confusion in V8
 * High CVE-2026-5866: Use after free in Media
 * High CVE-2026-5867: Heap buffer overflow in WebML
 * High CVE-2026-5868: Heap buffer overflow in ANGLE
 * High CVE-2026-5869: Heap buffer overflow in WebML
 * High CVE-2026-5870: Integer overflow in Skia
 * High CVE-2026-5871: Type Confusion in V8
 * High CVE-2026-5872: Use after free in Blink
 * High CVE-2026-5873: Out of bounds read and write in V8
 * Medium CVE-2026-5874: Use after free in PrivateAI
 * Medium CVE-2026-5875: Policy bypass in Blink
 * Medium CVE-2026-5876: Side-channel information leakage in Navigation
 * Medium CVE-2026-5877: Use after free in Navigation
 * Medium CVE-2026-5878: Incorrect security UI in Blink
 * Medium CVE-2026-5879: Insufficient validation of untrusted input in ANGLE
 * Medium CVE-2026-5880: Incorrect security UI in browser UI
 * Medium CVE-2026-5881: Policy bypass in LocalNetworkAccess
 * Medium CVE-2026-5882: Incorrect security UI in Fullscreen
 * Medium CVE-2026-5883: Use after free in Media
 * Medium CVE-2026-5884: Insufficient validation of untrusted input in Media
 * Medium CVE-2026-5885: Insufficient validation of untrusted input in WebML
 * Medium CVE-2026-5886: Out of bounds read in WebAudio
 * Medium CVE-2026-5887: Insufficient validation of untrusted input in Downloads
 * Medium CVE-2026-5888: Uninitialized Use in WebCodecs
 * Medium CVE-2026-5889: Cryptographic Flaw in PDFium
 * Medium CVE-2026-5890: Race in WebCodecs
 * Medium CVE-2026-5891: Insufficient policy enforcement in browser UI
 * Medium CVE-2026-5892: Insufficient policy enforcement in PWAs
 * Medium CVE-2026-5893: Race in V8
 * Low CVE-2026-5894: Inappropriate implementation in PDF
 * Low CVE-2026-5895: Incorrect security UI in Omnibox
 * Low CVE-2026-5896: Policy bypass in Audio
 * Low CVE-2026-5897: Incorrect security UI in Downloads
 * Low CVE-2026-5898: Incorrect security UI in Omnibox
 * Low CVE-2026-5899: Incorrect security UI in History Navigation
 * Low CVE-2026-5900: Policy bypass in Downloads
 * Low CVE-2026-5901: Policy bypass in DevTools
 * Low CVE-2026-5902: Race in Media
 * Low CVE-2026-5903: Policy bypass in IFrameSandbox
 * Low CVE-2026-5904: Use after free in V8
 * Low CVE-2026-5905: Incorrect security UI in Permissions
 * Low CVE-2026-5906: Incorrect security UI in Omnibox
 * Low CVE-2026-5907: Insufficient data validation in Media
 * Low CVE-2026-5908: Integer overflow in Media
 * Low CVE-2026-5909: Integer overflow in Media
 * Low CVE-2026-5910: Integer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui-debuginfo", rpm:"chromium-qt5-ui-debuginfo~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~147.0.7727.55~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui-debuginfo", rpm:"chromium-qt6-ui-debuginfo~147.0.7727.55~1.fc43", rls:"FC43"))) {
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
