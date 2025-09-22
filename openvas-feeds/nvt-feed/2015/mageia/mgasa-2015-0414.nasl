# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131106");
  script_cve_id("CVE-2015-4477", "CVE-2015-4483", "CVE-2015-4490", "CVE-2015-4500", "CVE-2015-4501", "CVE-2015-4502", "CVE-2015-4504", "CVE-2015-4507", "CVE-2015-4508", "CVE-2015-4509", "CVE-2015-4510", "CVE-2015-4511", "CVE-2015-4512", "CVE-2015-4516", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177");
  script_tag(name:"creation_date", value:"2015-10-27 10:54:49 +0000 (Tue, 27 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0414)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0414");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0414.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16842");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-102/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-103/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-104/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-105/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-106/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-107/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-108/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-109/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-110/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-111/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-112/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-81/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-86/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-91/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-96/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-98/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape, sqlite3' package(s) announced via the MGASA-2015-0414 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues. The sqlite3 package has been
updated as well since the new iceape version requires the
SQLITE_ENABLE_DBSTAT_VTAB feature to be enabled in sqlite. This sqlite3
update also enables ICU support, fixing bug #16814 .

Use-after-free vulnerability in the MediaStream playback feature in
Mozilla Firefox before 40.0 allows remote attackers to execute arbitrary
code via unspecified use of the Web Audio API. (CVE-2015-4477)

Mozilla Firefox before 40.0 allows man-in-the-middle attackers to bypass a
mixed-content protection mechanism via a feed: URL in a POST request.
(CVE-2015-4483)

The nsCSPHostSrc::permits function in dom/security/nsCSPUtils.cpp in
Mozilla Firefox before 40.0 does not implement the Content Security Policy
Level 2 exceptions for the blob, data, and filesystem URL schemes during
wildcard source-expression matching, which might make it easier for remote
attackers to conduct cross-site scripting (XSS) attacks by leveraging
unexpected policy-enforcement behavior. (CVE-2015-4490)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 41.0 and Firefox ESR 38.x before 38.3 allow remote
attackers to cause a denial of service (memory corruption and application
crash) or possibly execute arbitrary code via unknown vectors.
(CVE-2015-4500)

Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 41.0 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute arbitrary
code via unknown vectors. (CVE-2015-4501)

The lut_inverse_interp16 function in the QCMS library in Mozilla Firefox
before 41.0 allows remote attackers to obtain sensitive information or
cause a denial of service (buffer over-read and application crash) via
crafted attributes in the ICC 4 profile of an image. (CVE-2015-4504)

The SavedStacks class in the JavaScript implementation in Mozilla Firefox
before 41.0, when the Debugger API is enabled, allows remote attackers to
cause a denial of service (getSlotRef assertion failure and application
exit) or possibly execute arbitrary code via a crafted web site.
(CVE-2015-4507)

Mozilla Firefox before 41.0, when reader mode is enabled, allows remote
attackers to spoof the relationship between address-bar URLs and web
content via a crafted web site. (CVE-2015-4508)

Race condition in the WorkerPrivate::NotifyFeatures function in Mozilla
Firefox before 41.0 allows remote attackers to execute arbitrary code or
cause a denial of service (use-after-free and application crash) by
leveraging improper interaction between shared workers and the IndexedDB
implementation. (CVE-2015-4510)

Heap-based buffer overflow in the nestegg_track_codec_data function in
Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3 allows remote
attackers to execute arbitrary code via a crafted header in a WebM ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape, sqlite3' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.38~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lemon", rpm:"lemon~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-devel", rpm:"lib64sqlite3-devel~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3-static-devel", rpm:"lib64sqlite3-static-devel~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sqlite3_0", rpm:"lib64sqlite3_0~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-devel", rpm:"libsqlite3-devel~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3-static-devel", rpm:"libsqlite3-static-devel~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsqlite3_0", rpm:"libsqlite3_0~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3", rpm:"sqlite3~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tcl", rpm:"sqlite3-tcl~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sqlite3-tools", rpm:"sqlite3-tools~3.8.10.2~1.1.mga5", rls:"MAGEIA5"))) {
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
