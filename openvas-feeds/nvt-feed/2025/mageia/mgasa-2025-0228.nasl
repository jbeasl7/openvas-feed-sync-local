# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0228");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181");
  script_tag(name:"creation_date", value:"2025-09-08 04:07:54 +0000 (Mon, 08 Sep 2025)");
  script_version("2025-09-08T05:38:50+0000");
  script_tag(name:"last_modification", value:"2025-09-08 05:38:50 +0000 (Mon, 08 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2025-0228)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0228");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0228.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0332.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0336.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0350.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0365.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0384.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0395.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0010.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0048.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0093.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0126.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0151.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0168.html");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0197.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34415");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-55/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-62/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-71/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/128.12.0esr/releasenotes/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/128.13.0esr/releasenotes/");
  script_xref(name:"URL", value:"https://www.thunderbird.net/en-US/thunderbird/128.14.0esr/releasenotes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird, thunderbird-l10n' package(s) announced via the MGASA-2025-0228 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free in FontFaceSet. (CVE-2025-6424)
The WebCompat WebExtension shipped exposed a persistent UUID.
(CVE-2025-6425)
Incorrect parsing of URLs could have allowed embedding of youtube.com.
(CVE-2025-6429)
Content-Disposition header ignored when a file is included in an embed
or object tag. (CVE-2025-6430)
JavaScript engine only wrote partial return value to stack.
(CVE-2025-8027)
Large branch table could lead to truncated instruction. (CVE-2025-8028)
Javascript: URLs executed on object and embed tags. (CVE-2025-8029)
Potential user-assisted code execution in 'Copy as cURL' command.
(CVE-2025-8030)
Incorrect URL stripping in CSP reports. (CVE-2025-8031)
XSLT documents could bypass CSP. (CVE-2025-8032)
Incorrect JavaScript state machine for generators. (CVE-2025-8033)
Memory safety bugs fixed in Firefox ESR 115.26, Firefox ESR 128.13,
Thunderbird ESR 128.13, Firefox ESR 140.1, Thunderbird ESR 140.1,
Firefox 141 and Thunderbird 141. (CVE-2025-8034)
Memory safety bugs fixed in Firefox ESR 128.13, Thunderbird ESR 128.13,
Firefox ESR 140.1, Thunderbird ESR 140.1, Firefox 141 and Thunderbird
141. (CVE-2025-8035)
Sandbox escape due to invalid pointer in the Audio/Video: GMP component.
(CVE-2025-9179)
Same-origin policy bypass in the Graphics: Canvas2D component.
(CVE-2025-9180)
Uninitialized memory in the JavaScript Engine component. (CVE-2025-9181)
Memory safety bugs fixed in Firefox ESR 115.27, Firefox ESR 128.14,
Thunderbird ESR 128.14, Firefox ESR 140.2, Thunderbird ESR 140.2,
Firefox 142 and Thunderbird 142. (CVE-2025-9185).
For the armv7hl architecture this package fixes additional vulnerabilities,
see the links below:
[links moved to references]");

  script_tag(name:"affected", value:"'thunderbird, thunderbird-l10n' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-af", rpm:"thunderbird-af~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ar", rpm:"thunderbird-ar~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ast", rpm:"thunderbird-ast~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-be", rpm:"thunderbird-be~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-bg", rpm:"thunderbird-bg~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-br", rpm:"thunderbird-br~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ca", rpm:"thunderbird-ca~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cs", rpm:"thunderbird-cs~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-cy", rpm:"thunderbird-cy~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-da", rpm:"thunderbird-da~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-de", rpm:"thunderbird-de~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-dsb", rpm:"thunderbird-dsb~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-el", rpm:"thunderbird-el~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_CA", rpm:"thunderbird-en_CA~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_GB", rpm:"thunderbird-en_GB~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-en_US", rpm:"thunderbird-en_US~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_AR", rpm:"thunderbird-es_AR~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_ES", rpm:"thunderbird-es_ES~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-es_MX", rpm:"thunderbird-es_MX~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-et", rpm:"thunderbird-et~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-eu", rpm:"thunderbird-eu~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fi", rpm:"thunderbird-fi~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fr", rpm:"thunderbird-fr~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-fy_NL", rpm:"thunderbird-fy_NL~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ga_IE", rpm:"thunderbird-ga_IE~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gd", rpm:"thunderbird-gd~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-gl", rpm:"thunderbird-gl~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-he", rpm:"thunderbird-he~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hr", rpm:"thunderbird-hr~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hsb", rpm:"thunderbird-hsb~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hu", rpm:"thunderbird-hu~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-hy_AM", rpm:"thunderbird-hy_AM~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-id", rpm:"thunderbird-id~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-is", rpm:"thunderbird-is~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-it", rpm:"thunderbird-it~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ja", rpm:"thunderbird-ja~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ka", rpm:"thunderbird-ka~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-kab", rpm:"thunderbird-kab~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-kk", rpm:"thunderbird-kk~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ko", rpm:"thunderbird-ko~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-l10n", rpm:"thunderbird-l10n~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lt", rpm:"thunderbird-lt~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-lv", rpm:"thunderbird-lv~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ms", rpm:"thunderbird-ms~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nb_NO", rpm:"thunderbird-nb_NO~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nl", rpm:"thunderbird-nl~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-nn_NO", rpm:"thunderbird-nn_NO~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pa_IN", rpm:"thunderbird-pa_IN~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pl", rpm:"thunderbird-pl~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_BR", rpm:"thunderbird-pt_BR~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-pt_PT", rpm:"thunderbird-pt_PT~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ro", rpm:"thunderbird-ro~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-ru", rpm:"thunderbird-ru~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sk", rpm:"thunderbird-sk~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sl", rpm:"thunderbird-sl~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sq", rpm:"thunderbird-sq~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sr", rpm:"thunderbird-sr~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-sv_SE", rpm:"thunderbird-sv_SE~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-th", rpm:"thunderbird-th~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-tr", rpm:"thunderbird-tr~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uk", rpm:"thunderbird-uk~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-uz", rpm:"thunderbird-uz~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-vi", rpm:"thunderbird-vi~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_CN", rpm:"thunderbird-zh_CN~128.14.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"thunderbird-zh_TW", rpm:"thunderbird-zh_TW~128.14.0~1.mga9", rls:"MAGEIA9"))) {
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
