# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130090");
  script_cve_id("CVE-2015-1271", "CVE-2015-1272", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1276", "CVE-2015-1277", "CVE-2015-1278", "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282", "CVE-2015-1284", "CVE-2015-1285", "CVE-2015-1286", "CVE-2015-1287", "CVE-2015-1288", "CVE-2015-1289");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:35 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-07-23 14:15:45 +0000 (Thu, 23 Jul 2015)");

  script_name("Mageia: Security Advisory (MGASA-2015-0288)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0288");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0288.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/07/stable-channel-update_21.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/07/stable-channel-update_24.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16444");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0288 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 44.0.2403.107 fixes several security issues:

PDFium, as used in Google Chrome before 44.0.2403.89, does not properly
handle certain out-of-memory conditions, which allows remote attackers to
cause a denial of service (heap-based buffer overflow) or possibly have
unspecified other impact via a crafted PDF document that triggers a large
memory allocation. (CVE-2015-1271)

Use-after-free vulnerability in the GPU process implementation in Google
Chrome before 44.0.2403.89 allows remote attackers to cause a denial of
service or possibly have unspecified other impact by leveraging the
continued availability of a GPUChannelHost data structure during Blink
shutdown, related to
content/browser/gpu/browser_gpu_channel_host_factory.cc and
content/renderer/render_thread_impl.cc. (CVE-2015-1272)

Heap-based buffer overflow in j2k.c in OpenJPEG before r3002, as used in
PDFium in Google Chrome before 44.0.2403.89, allows remote attackers to
cause a denial of service or possibly have unspecified other impact via
invalid JPEG2000 data in a PDF document. (CVE-2015-1273)

Google Chrome before 44.0.2403.89 does not ensure that the auto-open list
omits all dangerous file types, which makes it easier for remote attackers
to execute arbitrary code by providing a crafted file and leveraging a
user's previous 'Always open files of this type' choice, related to
download_commands.cc and download_prefs.cc. (CVE-2015-1274)

Use-after-free vulnerability in
content/browser/indexed_db/indexed_db_backing_store.cc in the IndexedDB
implementation in Google Chrome before 44.0.2403.89 allows remote
attackers to cause a denial of service or possibly have unspecified other
impact by leveraging an abort action before a certain write operation.
(CVE-2015-1276)

Use-after-free vulnerability in the accessibility implementation in Google
Chrome before 44.0.2403.89 allows remote attackers to cause a denial of
service or possibly have unspecified other impact by leveraging lack of
certain validity checks for accessibility-tree data structures.
(CVE-2015-1277)

content/browser/web_contents/web_contents_impl.cc in Google Chrome before
44.0.2403.89 does not ensure that a PDF document's modal dialog is closed
upon navigation to an interstitial page, which allows remote attackers to
spoof URLs via a crafted document, as demonstrated by the alert_dialog.pdf
document. (CVE-2015-1278)

Integer overflow in the CJBig2_Image::expand function in
fxcodec/jbig2/JBig2_Image.cpp in PDFium, as used in Google Chrome before
44.0.2403.89, allows remote attackers to cause a denial of service
(heap-based buffer overflow) or possibly have unspecified other impact via
large height and stride values. (CVE-2015-1279)

SkPictureShader.cpp in Skia, as used in Google Chrome before 44.0.2403.89,
allows remote attackers to cause a denial of service (memory corruption)
or possibly have unspecified other impact by leveraging ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~44.0.2403.107~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~44.0.2403.107~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~44.0.2403.107~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~44.0.2403.107~1.mga5", rls:"MAGEIA5"))) {
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
