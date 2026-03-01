# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20435.1");
  script_cve_id("CVE-2025-15269", "CVE-2025-15275", "CVE-2025-15279", "CVE-2025-50949");
  script_tag(name:"creation_date", value:"2026-02-20 04:36:11 +0000 (Fri, 20 Feb 2026)");
  script_version("2026-02-20T05:55:45+0000");
  script_tag(name:"last_modification", value:"2026-02-20 05:55:45 +0000 (Fri, 20 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20435-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620435-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256032");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024340.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fontforge' package(s) announced via the SUSE-SU-2026:20435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for fontforge fixes the following issues:

Update to version 20251009.

Security issues fixed:

- CVE-2025-15279: remote code execution via heap-based buffer overflow in BMP file parsing (bsc#1256013).
- CVE-2025-15269: remote code execution via use-after-free in SFD file parsing (bsc#1256032).
- CVE-2025-15275: arbitrary code execution via SFD file parsing buffer overflow (bsc#1256025).
- CVE-2025-50949: memory leak in function DlgCreate8 (bsc#1252652).

Other updates and bugfixes:

- fix multiple crashes in Multiple Masters.
- fix crash for content over 32767 characters in GDraw multiline text field.
- fix crash on Up/Down
- fix crash in Metrics View.
- fix UFO crash for empty contours.
- fix crash issue in allmarkglyphs.

- Version update to 20251009:

 * Update documentation for py scripts (#5180)
 * Update GitHub CI runners (#5328)
 * Update po files from Croudin sources. (#5330)
 * Use consistent Python in MacOS GitHub runner (#5331)
 * Fix CI for Windows GitHub runner (#5335)
 * Fix lookup flags parsing (#5338)
 * Fixes (#5332): glyph file names uXXXXX (#5333)
 * make harmonization robust and avoid zero handles after harmonization (#5262)
 * Quiet strict prototypes warnings. (#5313)
 * Fix crash in parsegvar() due to insufficient buffer (#5339)
 * Handle failed iconv conversion. Unhandled execution path was UB, causing a segfault for me (#5329)
 * Fix CMake function _get_git_version() (#5342)
 * Don't require individual tuple encapsulation in fontforge.font.bitmapSizes setter (#5138)
 * nltransform of anchor points (#5345)
 * Fix generateFontPostHook being called instead of generateFontPreHook (#5226)
 * Always set usDefaultChar to 0 (.notdef) (#5242)
 * add font attributes, method to Python docs (#5353)
 * fix segfault triggered by Python del c[i:j] (#5352)
 * Autoselect internal WOFF2 format (#5346)
 * Fix typos in the FAQ (#5355)
 * add font.style_set_names attribute to Python API (#5354)
 * Bulk tester (#5365)
 * Fix Splinefont shell invocation (#5367)
 * Fix the lists of Windows language IDs (#5359)
 * Support suplementary planes in SFD (emojis etc.) (#5364)
 * Remove psaltnames for multi-code-point names (#5305)
 * doc: added missing sudo to installation instructions (#5300)
 * Fix data corruption on SFD reading (#5380)
 * Compare vertical metrics check when generating TTC (#5372)
 * Treat FT_PIXEL_MODE_MONO as 2 grey levels (#5379)
 * Don't attempt to copy anchors into NULL font (#5405)
 * Fix export of supplementary plane characters in font name to TTF (#5396)
 * Defer crowdin update to the end of the pipeline (#5409)
 * Fix generated feature file bugs (#5384)
 * crowdin: update to java 17 (#5447)
 * Remove assert from Python script processor (#5410)
 * Use sysconfig for Python module locations (#5423)
 * Use PyConfig API on Python 3.8 (#5404)
 * Fix resource leak in unParseTTInstrs (#5476)
 * Only install GUI-specific files if ENABLE_GUI is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fontforge' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"fontforge", rpm:"fontforge~20251009~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-devel", rpm:"fontforge-devel~20251009~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-doc", rpm:"fontforge-doc~20251009~160000.1.1", rls:"SLES16.0.0"))) {
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
