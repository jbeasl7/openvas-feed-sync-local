# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892804");
  script_cve_id("CVE-2019-13616", "CVE-2019-7572", "CVE-2019-7573", "CVE-2019-7574", "CVE-2019-7575", "CVE-2019-7576", "CVE-2019-7577", "CVE-2019-7578", "CVE-2019-7635", "CVE-2019-7636", "CVE-2019-7637", "CVE-2019-7638");
  script_tag(name:"creation_date", value:"2021-11-01 02:00:24 +0000 (Mon, 01 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-08 13:43:00 +0000 (Fri, 08 Feb 2019)");

  script_name("Debian: Security Advisory (DLA-2804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2804-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2804-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libsdl1.2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libsdl1.2' package(s) announced via the DLA-2804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerability have been fixed in libsdl2, the older version of the Simple DirectMedia Layer library that provides low level access to audio, keyboard, mouse, joystick, and graphics hardware.

CVE-2019-7572

Buffer over-read in IMA_ADPCM_nibble in audio/SDL_wave.c

CVE-2019-7573

Heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c

CVE-2019-7574

Heap-based buffer over-read in IMA_ADPCM_decode in audio/SDL_wave.c

CVE-2019-7575

Heap-based buffer overflow in MS_ADPCM_decode in audio/SDL_wave.c

CVE-2019-7576

Heap-based buffer over-read in InitMS_ADPCM in audio/SDL_wave.c

CVE-2019-7577

Buffer over-read in SDL_LoadWAV_RW in audio/SDL_wave.c

CVE-2019-7578

Heap-based buffer over-read in InitIMA_ADPCM in audio/SDL_wave.c

CVE-2019-7635

Heap-based buffer over-read in Blit1to4 in video/SDL_blit_1.c

CVE-2019-7636

Heap-based buffer over-read in SDL_GetRGB in video/SDL_pixels.c

CVE-2019-7637

Heap-based buffer overflow in SDL_FillRect in video/SDL_surface.c

CVE-2019-7638

Heap-based buffer over-read in Map1toN in video/SDL_pixels.c

CVE-2019-13616

Heap-based buffer over-read in BlitNtoN in video/SDL_blit_N.c

For Debian 9 stretch, these problems have been fixed in version 1.2.15+dfsg1-4+deb9u1.

We recommend that you upgrade your libsdl1.2 packages.

For the detailed security status of libsdl1.2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libsdl1.2' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"libsdl1.2-dev", ver:"1.2.15+dfsg1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsdl1.2debian", ver:"1.2.15+dfsg1-4+deb9u1", rls:"DEB9"))) {
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
