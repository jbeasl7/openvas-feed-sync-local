# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130044");
  script_cve_id("CVE-2015-0799", "CVE-2015-0801", "CVE-2015-0802", "CVE-2015-0803", "CVE-2015-0804", "CVE-2015-0805", "CVE-2015-0806", "CVE-2015-0807", "CVE-2015-0808", "CVE-2015-0811", "CVE-2015-0812", "CVE-2015-0813", "CVE-2015-0814", "CVE-2015-0815", "CVE-2015-0816", "CVE-2015-2706", "CVE-2015-2708", "CVE-2015-2709", "CVE-2015-2710", "CVE-2015-2711", "CVE-2015-2712", "CVE-2015-2713", "CVE-2015-2715", "CVE-2015-2716", "CVE-2015-2717", "CVE-2015-2718", "CVE-2015-4496");
  script_tag(name:"creation_date", value:"2015-10-15 07:41:56 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0342");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0342.html");
  script_xref(name:"URL", value:"http://www.seamonkey-project.org/releases/seamonkey2.35/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16698");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-30/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-31/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-32/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-33/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-34/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-36/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-37/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-38/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-39/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-40/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-42/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-44/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-45/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-46/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-48/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-49/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-51/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-53/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-54/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-55/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-56/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-93/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2015-0342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated iceape packages fix security issues:

Multiple unspecified vulnerabilities in the browser engine in Mozilla Firefox
before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 allow
remote attackers to cause a denial of service (memory corruption and application
crash) or possibly execute arbitrary code via unknown vectors. (CVE-2015-0814,
CVE-2015-0815)

Use-after-free vulnerability in the AppendElements function in Mozilla Firefox
before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird before 31.6 on Linux,
when the Fluendo MP3 plugin for GStreamer is used, allows remote attackers to
execute arbitrary code or cause a denial of service (heap memory corruption) via
a crafted MP3 file. (CVE-2015-0813)

Mozilla Firefox before 37.0 does not require an HTTPS session for lightweight
theme add-on installations, which allows man-in-the-middle attackers to bypass
an intended user-confirmation requirement by deploying a crafted web site and
conducting a DNS spoofing attack against a mozilla.org subdomain.
(CVE-2015-0812)

Mozilla Firefox before 37.0, Firefox ESR 31.x before 31.6, and Thunderbird
before 31.6 do not properly restrict resource: URLs, which makes it easier for
remote attackers to execute arbitrary JavaScript code with chrome privileges by
leveraging the ability to bypass the Same Origin Policy, as demonstrated by the
resource: URL associated with PDF.js. (CVE-2015-0816)

The QCMS implementation in Mozilla Firefox before 37.0 allows remote attackers
to obtain sensitive information from process heap memory or cause a denial of
service (out-of-bounds read) via an image that is improperly handled during
transformation. (CVE-2015-0811)

The webrtc::VPMContentAnalysis::Release function in the WebRTC implementation in
Mozilla Firefox before 37.0 uses incompatible approaches to the deallocation of
memory for simple-type arrays, which might allow remote attackers to cause a
denial of service (memory corruption) via unspecified vectors. (CVE-2015-0808)

The navigator.sendBeacon implementation in Mozilla Firefox before 37.0, Firefox
ESR 31.x before 31.6, and Thunderbird before 31.6 processes HTTP 30x status
codes for redirects after a preflight request has occurred, which allows remote
attackers to bypass intended CORS access-control checks and conduct cross-site
request forgery (CSRF) attacks via a crafted web site, a similar issue to
CVE-2014-8638. (CVE-2015-0807)

The Off Main Thread Compositing (OMTC) implementation in Mozilla Firefox before
37.0 makes an incorrect memset call during interaction with the
mozilla::layers::BufferTextureClient::AllocateForSurface function, which allows
remote attackers to execute arbitrary code or cause a denial of service (memory
corruption and application crash) via vectors that trigger rendering of 2D
graphics content. (CVE-2015-0805)

The Off Main Thread Compositing (OMTC) implementation in Mozilla Firefox before
37.0 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.35~1.mga4", rls:"MAGEIA4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.35~1.mga5", rls:"MAGEIA5"))) {
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
