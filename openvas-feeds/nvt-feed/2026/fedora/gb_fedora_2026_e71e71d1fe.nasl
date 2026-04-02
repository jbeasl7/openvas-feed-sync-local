# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10171101711001102101");
  script_cve_id("CVE-2026-3913", "CVE-2026-3914", "CVE-2026-3915", "CVE-2026-3916", "CVE-2026-3917", "CVE-2026-3918", "CVE-2026-3919", "CVE-2026-3920", "CVE-2026-3921", "CVE-2026-3922", "CVE-2026-3923", "CVE-2026-3924", "CVE-2026-3925", "CVE-2026-3926", "CVE-2026-3927", "CVE-2026-3928", "CVE-2026-3929", "CVE-2026-3930", "CVE-2026-3931", "CVE-2026-3932", "CVE-2026-3934", "CVE-2026-3935", "CVE-2026-3936", "CVE-2026-3937", "CVE-2026-3938", "CVE-2026-3939", "CVE-2026-3940", "CVE-2026-3941", "CVE-2026-3942");
  script_tag(name:"creation_date", value:"2026-03-16 04:56:17 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-16 12:45:41 +0000 (Mon, 16 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-e71e71d1fe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-e71e71d1fe");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-e71e71d1fe");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2026-e71e71d1fe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 146.0.7680.71

 * CVE-2026-3913: Heap buffer overflow in WebML
 * CVE-2026-3914: Integer overflow in WebML
 * CVE-2026-3915: Heap buffer overflow in WebML
 * CVE-2026-3916: Out of bounds read in Web Speech
 * CVE-2026-3917: Use after free in Agents
 * CVE-2026-3918: Use after free in WebMCP
 * CVE-2026-3919: Use after free in Extensions
 * CVE-2026-3920: Out of bounds memory access in WebML
 * CVE-2026-3921: Use after free in TextEncoding
 * CVE-2026-3922: Use after free in MediaStream
 * CVE-2026-3923: Use after free in WebMIDI
 * CVE-2026-3924: Use after free in WindowDialog
 * CVE-2026-3925: Incorrect security UI in LookalikeChecks
 * CVE-2026-3926: Out of bounds read in V8
 * CVE-2026-3927: Incorrect security UI in PictureInPicture
 * CVE-2026-3928: Insufficient policy enforcement in Extensions
 * CVE-2026-3929: Side-channel information leakage in ResourceTiming
 * CVE-2026-3930: Unsafe navigation in Navigation
 * CVE-2026-3931: Heap buffer overflow in Skia
 * CVE-2026-3932: Insufficient policy enforcement in PDF
 * CVE-2026-3934: Insufficient policy enforcement in ChromeDriver
 * CVE-2026-3935: Incorrect security UI in WebAppInstalls
 * CVE-2026-3936: Use after free in WebView
 * CVE-2026-3937: Incorrect security UI in Downloads
 * CVE-2026-3938: Insufficient policy enforcement in Clipboard
 * CVE-2026-3939: Insufficient policy enforcement in PDF
 * CVE-2026-3940: Insufficient policy enforcement in DevTools
 * CVE-2026-3941: Insufficient policy enforcement in DevTools
 * CVE-2026-3942: Incorrect security UI in PictureInPicture");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common-debuginfo", rpm:"chromium-common-debuginfo~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless-debuginfo", rpm:"chromium-headless-debuginfo~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui-debuginfo", rpm:"chromium-qt5-ui-debuginfo~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~146.0.7680.71~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui-debuginfo", rpm:"chromium-qt6-ui-debuginfo~146.0.7680.71~1.fc42", rls:"FC42"))) {
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
