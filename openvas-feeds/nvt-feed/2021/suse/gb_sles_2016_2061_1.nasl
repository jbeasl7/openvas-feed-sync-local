# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2061.1");
  script_cve_id("CVE-2016-2815", "CVE-2016-2818", "CVE-2016-2819", "CVE-2016-2821", "CVE-2016-2822", "CVE-2016-2824", "CVE-2016-2828", "CVE-2016-2830", "CVE-2016-2831", "CVE-2016-2834", "CVE-2016-2835", "CVE-2016-2836", "CVE-2016-2837", "CVE-2016-2838", "CVE-2016-2839", "CVE-2016-5252", "CVE-2016-5254", "CVE-2016-5258", "CVE-2016-5259", "CVE-2016-5262", "CVE-2016-5263", "CVE-2016-5264", "CVE-2016-5265", "CVE-2016-6354");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-22 00:58:06 +0000 (Thu, 22 Sep 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2061-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2061-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162061-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991809");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002206.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLED, mozilla-nspr and mozilla-nss' package(s) announced via the SUSE-SU-2016:2061-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nspr and mozilla-nss were updated to fix nine security issues.

MozillaFirefox was updated to version 45.3.0 ESR. mozilla-nss was updated to version 3.21.1, mozilla-nspr to version 4.12.

These security issues were fixed in 45.3.0ESR:
- CVE-2016-2835/CVE-2016-2836: Miscellaneous memory safety hazards (rv:48.0 / rv:45.3) (MFSA 2016-62)
- CVE-2016-2830: Favicon network connection can persist when page is closed (MFSA 2016-63)
- CVE-2016-2838: Buffer overflow rendering SVG with bidirectional content (MFSA 2016-64)
- CVE-2016-2839: Cairo rendering crash due to memory allocation issue with FFmpeg 0.10 (MFSA 2016-65)
- CVE-2016-5252: Stack underflow during 2D graphics rendering (MFSA 2016-67)
- CVE-2016-5254: Use-after-free when using alt key and toplevel menus (MFSA 2016-70)
- CVE-2016-5258: Use-after-free in DTLS during WebRTC session shutdown (MFSA 2016-72)
- CVE-2016-5259: Use-after-free in service workers with nested sync events (MFSA 2016-73)
- CVE-2016-5262: Scripts on marquee tag can execute in sandboxed iframes (MFSA 2016-76)
- CVE-2016-2837: Buffer overflow in ClearKey Content Decryption Module (CDM) during video playback (MFSA 2016-77)
- CVE-2016-5263: Type confusion in display transformation (MFSA 2016-78)
- CVE-2016-5264: Use-after-free when applying SVG effects (MFSA 2016-79)
- CVE-2016-5265: Same-origin policy violation using local HTML file and saved shortcut file (MFSA 2016-80)
- CVE-2016-6354: Fix for possible buffer overrun (bsc#990856)

Security issues fixed in 45.2.0.ESR:
- CVE-2016-2834: Memory safety bugs in NSS (MFSA 2016-61) (bsc#983639).
- CVE-2016-2824: Out-of-bounds write with WebGL shader (MFSA 2016-53) (bsc#983651).
- CVE-2016-2822: Addressbar spoofing though the SELECT element (MFSA 2016-52) (bsc#983652).
- CVE-2016-2821: Use-after-free deleting tables from a contenteditable document (MFSA 2016-51) (bsc#983653).
- CVE-2016-2819: Buffer overflow parsing HTML5 fragments (MFSA 2016-50) (bsc#983655).
- CVE-2016-2828: Use-after-free when textures are used in WebGL operations after recycle pool destruction (MFSA 2016-56) (bsc#983646).
- CVE-2016-2831: Entering fullscreen and persistent pointerlock without user permission (MFSA 2016-58) (bsc#983643).
- CVE-2016-2815, CVE-2016-2818: Miscellaneous memory safety hazards (MFSA 2016-49) (bsc#983638)

These non-security issues were fixed:
- Fix crashes on aarch64
 * Determine page size at runtime (bsc#984006)
 * Allow aarch64 to work in safe mode (bsc#985659)
- Fix crashes on mainframes
- Temporarily bind Firefox to the first CPU as a hotfix
 for an apparent race condition (bsc#989196, bsc#990628)

All extensions must now be signed by addons.mozilla.org. Please read README.SUSE for more details.");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLED, mozilla-nspr and mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~45.3.0esr~48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~45.0~20.38", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~45.3.0esr~48.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fontconfig", rpm:"firefox-fontconfig~2.11.0~4.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.21.1~26.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.21.1~26.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.12~25.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.12~25.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.12~25.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.21.1~26.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.21.1~26.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.21.1~26.2", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.21.1~26.2", rls:"SLES11.0SP2"))) {
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
