# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1353.1");
  script_cve_id("CVE-2018-6942");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:02 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 14:20:28 +0000 (Fri, 16 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1353-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201353-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freetype2' package(s) announced via the SUSE-SU-2020:1353-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freetype2 to version 2.10.1 fixes the following issues:

Security issue fixed:

CVE-2018-6942: Fixed a NULL pointer dereference within ttinerp.c
 (bsc#1079603).

Non-security issues fixed:

Update to version 2.10.1
 * The bytecode hinting of OpenType variation fonts was flawed, since the
 data in the `CVAR' table wasn't correctly applied.
 * Auto-hinter support for Mongolian.
 * The handling of the default character in PCF fonts as introduced in
 version 2.10.0 was partially broken, causing premature abortion
 of charmap iteration for many fonts.
 * If `FT_Set_Named_Instance' was called with the same arguments
 twice in a row, the function returned an incorrect error code the
 second time.
 * Direct rendering using FT_RASTER_FLAG_DIRECT crashed (bug
 introduced in version 2.10.0).
 * Increased precision while computing OpenType font variation
 instances.
 * The flattening algorithm of cubic Bezier curves was slightly
 changed to make it faster. This can cause very subtle rendering
 changes, which aren't noticeable by the eye, however.
 * The auto-hinter now disables hinting if there are blue zones
 defined for a `style' (i.e., a certain combination of a script and its
 related typographic features) but the font doesn't contain any
 characters needed to set up at least one blue zone.

Add tarball signatures and freetype2.keyring

Update to version 2.10.0
 * A bunch of new functions has been added to access and process
 COLR/CPAL data of OpenType fonts with color-layered glyphs.
 * As a GSoC 2018 project, Nikhil Ramakrishnan completely
 overhauled and modernized the API reference.
 * The logic for computing the global ascender, descender, and height of
 OpenType fonts has been slightly adjusted for consistency.
 * `TT_Set_MM_Blend' could fail if called repeatedly with the same
 arguments.
 * The precision of handling deltas in Variation Fonts has been
 increased.The problem did only show up with multidimensional
 designspaces.
 * New function `FT_Library_SetLcdGeometry' to set up the geometry
 of LCD subpixels.
 * FreeType now uses the `defaultChar' property of PCF fonts to set the
 glyph for the undefined character at glyph index 0 (as FreeType
 already does for all other supported font formats). As a consequence,
 the order of glyphs of a PCF font if accessed with FreeType can be
 different now compared to previous versions. This change doesn't
 affect PCF font access with cmaps.
 * `FT_Select_Charmap' has been changed to allow parameter value
 `FT_ENCODING_NONE', which is valid for BDF, PCF, and Windows FNT
 formats to access built-in cmaps that don't have a predefined
 `FT_Encoding' value.
 * A previously reserved field in the `FT_GlyphSlotRec' structure now
 holds the glyph index.
 * The usual round of fuzzer bug fixes to better reject malformed fonts.
 * `FT_Outline_New_Internal' and `FT_Outline_Done_Internal' have been
 removed.These two functions ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'freetype2' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"freetype2-debugsource", rpm:"freetype2-debugsource~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freetype2-devel", rpm:"freetype2-devel~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6", rpm:"libfreetype6~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit", rpm:"libfreetype6-32bit~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-32bit-debuginfo", rpm:"libfreetype6-32bit-debuginfo~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreetype6-debuginfo", rpm:"libfreetype6-debuginfo~2.10.1~4.3.1", rls:"SLES15.0SP1"))) {
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
