# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0062");
  script_cve_id("CVE-2022-38850", "CVE-2022-38851", "CVE-2022-38855", "CVE-2022-38858", "CVE-2022-38860", "CVE-2022-38861", "CVE-2022-38863", "CVE-2022-38864", "CVE-2022-38865", "CVE-2022-38866");
  script_tag(name:"creation_date", value:"2024-03-15 04:12:49 +0000 (Fri, 15 Mar 2024)");
  script_version("2024-03-15T05:06:15+0000");
  script_tag(name:"last_modification", value:"2024-03-15 05:06:15 +0000 (Fri, 15 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-19 18:01:29 +0000 (Mon, 19 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2024-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0062.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31360");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mplayer' package(s) announced via the MGASA-2024-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The MPlayer Project mencoder SVN-r38374-13.0.1 is vulnerable to Divide
By Zero via the function config () of llibmpcodecs/vf_scale.c.
(CVE-2022-38850)
Certain The MPlayer Project products are vulnerable to Out-of-bounds
Read via function read_meta_record() of mplayer/libmpdemux/asfheader.c.
This affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
(CVE-2022-38851)
Certain The MPlayer Project products are vulnerable to Buffer Overflow
via function gen_sh_video () of mplayer/libmpdemux/demux_mov.c. This
affects mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
(CVE-2022-38855)
Certain The MPlayer Project products are vulnerable to Buffer Overflow
via function mov_build_index() of libmpdemux/demux_mov.c. This affects
mplayer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
(CVE-2022-38858)
Certain The MPlayer Project products are vulnerable to Divide By Zero
via function demux_open_avi() of libmpdemux/demux_avi.c which affects
mencoder. This affects mplayer SVN-r38374-13.0.1 and mencoder
SVN-r38374-13.0.1. (CVE-2022-38860)
The MPlayer Project mplayer SVN-r38374-13.0.1 is vulnerable to memory
corruption via function free_mp_image() of libmpcodecs/mp_image.c.
(CVE-2022-38861)
Certain The MPlayer Project products are vulnerable to Buffer Overflow
via function mp_getbits() of libmpdemux/mpeg_hdr.c which affects
mencoder and mplayer. This affects mecoder SVN-r38374-13.0.1 and mplayer
SVN-r38374-13.0.1. (CVE-2022-38863)
Certain The MPlayer Project products are vulnerable to Buffer Overflow
via the function mp_unescape03() of libmpdemux/mpeg_hdr.c. This affects
mencoder SVN-r38374-13.0.1 and mplayer SVN-r38374-13.0.1.
(CVE-2022-38864)
Certain The MPlayer Project products are vulnerable to Divide By Zero
via the function demux_avi_read_packet of libmpdemux/demux_avi.c. This
affects mplyer SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1.
(CVE-2022-38865)
Certain The MPlayer Project products are vulnerable to Buffer Overflow
via read_avi_header() of libmpdemux/aviheader.c . This affects mplayer
SVN-r38374-13.0.1 and mencoder SVN-r38374-13.0.1. (CVE-2022-38866)");

  script_tag(name:"affected", value:"'mplayer' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"mencoder", rpm:"mencoder~1.5~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mencoder", rpm:"mencoder~1.5~12.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer", rpm:"mplayer~1.5~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer", rpm:"mplayer~1.5~12.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer-doc", rpm:"mplayer-doc~1.5~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer-doc", rpm:"mplayer-doc~1.5~12.1.mga9.tainted", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer-gui", rpm:"mplayer-gui~1.5~12.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mplayer-gui", rpm:"mplayer-gui~1.5~12.1.mga9.tainted", rls:"MAGEIA9"))) {
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
