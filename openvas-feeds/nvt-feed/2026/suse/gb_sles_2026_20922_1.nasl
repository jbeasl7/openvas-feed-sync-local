# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20922.1");
  script_cve_id("CVE-2026-22693");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20922-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20922-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620922-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256459");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2026-April/045230.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'harfbuzz' package(s) announced via the SUSE-SU-2026:20922-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-22693: Fixed a NULL pointer dereference in SubtableUnicodesCache::create (bsc#1256459).

Other fixes:

 - Bug fixes for 'AAT' shaping, and other shaping micro
 optimizations.
 - Fix a shaping regression affecting mark glyphs in certain
 fonts.
 - Fix pruning of mark filtering sets when subsetting fonts, which
 caused changes in shaping behaviour.
 - Make shaping fail much faster for certain malformed fonts
 (e.g., those that trigger infinite recursion).
 - Fix undefined behaviour introduced in 11.4.2.
 - Fix detection of the 'Cambria Math' font when fonts are scaled,
 so the workaround for the bad MATH table constant is applied.
 - Various performance and memory usage improvements.
 - The hb-shape command line tool can now be built with the
 amalgamated harfbuzz.cc source.
 - Fix regression in handling version 2 of avar table.
 - Increase various buffer length limits for better handling of
 fonts that generate huge number of glyphs per codepoint (e.g.
 Noto Sans Duployan).
 - Improvements to the harfrust shaper for more accurate testing.
 - Fix clang compiler warnings.
 - General shaping and subsetting speedups.
 - Fix in Graphite shaping backend when glyph advances became
 negative.
 - Subsetting improvements, pruning empty mark-attachment lookups.
 - Don't use the macro name _S, which is reserved by system
 liberaries.
 - Build fixes and speedup.
 - Add a kbts shaping backend that calls into the kb_text_shape
 single-header shaping library. This is purely for testing and
 performance evaluation and we do NOT recommend using it for any
 other purposes.
 - Fix bug in vertical shaping of fonts without the vmtx table.
 - Fix build with non-compliant C++11 compilers that don't
 recognize the 'and' keyword.
 - Fix crasher in the glyph_v_origin function introduced in
 11.3.0.
 - Speed up handling fonts with very large number of variations.
 - Speed up getting horizontal and vertical glyph advances by up
 to 24%.
 - Significantly speed up vertical text shaping.
 - Various documentation improvements.
 - Various build improvements.
 - Various subsetting improvements.
 - Various improvements to Rust font functions (fontations
 integration) and shaper (HarfRust integration).
 - Rename harfruzz option and shaper to harfrust following
 upstream rename.
 - Implement hb_face_reference_blob() for DirectWrite font
 functions.
 - Various build improvements.
 - Fix build with HB_NO_DRAW and HB_NO_PAINT.
 - Add an optional harfruzz shaper that uses HarfRuzz, an ongoing
 Rust port of HarfBuzz shaping. This shaper is mainly used for
 testing the output of the Rust implementation.
 - Fix regression that caused applying unsafe_to_break() to the
 whole buffer to be ignored.
 - Update USE data files.
 - Fix getting advances of out-of-rage glyph indices in
 DirectWrite font functions.
 - Painting of COLRv1 fonts without clip boxes is now about 10
 times faster.
 - Synthetic bold/slant ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'harfbuzz' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-devel", rpm:"harfbuzz-devel~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-tools", rpm:"harfbuzz-tools~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-cairo0", rpm:"libharfbuzz-cairo0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-gobject0", rpm:"libharfbuzz-gobject0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0", rpm:"libharfbuzz-icu0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-subset0", rpm:"libharfbuzz-subset0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0", rpm:"libharfbuzz0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-HarfBuzz-0_0", rpm:"typelib-1_0-HarfBuzz-0_0~11.4.5~160000.1.1", rls:"SLES16.0.0"))) {
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
