# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0950.1");
  script_cve_id("CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-08 13:43:00 +0000 (Fri, 08 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0950-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0950-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190950-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2' package(s) announced via the SUSE-SU-2019:0950-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2 fixes the following issues:

Security issues fixed:
CVE-2019-7572: Fixed a buffer over-read in IMA_ADPCM_nibble in
 audio/SDL_wave.c.(bsc#1124806).

CVE-2019-7578: Fixed a heap-based buffer over-read in InitIMA_ADPCM in
 audio/SDL_wave.c (bsc#1125099).

CVE-2019-7576: Fixed heap-based buffer over-read in InitMS_ADPCM in
 audio/SDL_wave.c (bsc#1124799).

CVE-2019-7573: Fixed a heap-based buffer over-read in InitMS_ADPCM in
 audio/SDL_wave.c (bsc#1124805).

CVE-2019-7635: Fixed a heap-based buffer over-read in Blit1to4 in
 video/SDL_blit_1.c. (bsc#1124827).

CVE-2019-7636: Fixed a heap-based buffer over-read in SDL_GetRGB in
 video/SDL_pixels.c (bsc#1124826).

CVE-2019-7638: Fixed a heap-based buffer over-read in Map1toN in
 video/SDL_pixels.c (bsc#1124824).

CVE-2019-7574: Fixed a heap-based buffer over-read in IMA_ADPCM_decode
 in audio/SDL_wave.c (bsc#1124803).

CVE-2019-7575: Fixed a heap-based buffer overflow in MS_ADPCM_decode in
 audio/SDL_wave.c (bsc#1124802).

CVE-2019-7637: Fixed a heap-based buffer overflow in SDL_FillRect
 function in SDL_surface.c (bsc#1124825).

CVE-2019-7577: Fixed a buffer over read in SDL_LoadWAV_RW in
 audio/SDL_wave.c (bsc#1124800).");

  script_tag(name:"affected", value:"'SDL2' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~3.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~3.9.1", rls:"SLES15.0"))) {
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
