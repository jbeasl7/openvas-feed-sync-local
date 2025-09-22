# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0223");
  script_cve_id("CVE-2018-15822");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-01 13:03:54 +0000 (Thu, 01 Nov 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0223");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0223.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24099");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24104");
  script_xref(name:"URL", value:"https://www.mythtv.org/wiki/Release_Notes_-_29");
  script_xref(name:"URL", value:"https://www.mythtv.org/wiki/Release_Notes_-_30");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hdhomerun, mythtv, mythtv-mythweb' package(s) announced via the MGASA-2019-0223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides and update to mythtv 30, and updates the bundled
ffmpeg to 3.2. It also fixes at least the following issue:

The flv_write_packet function in libavformat/flvenc.c in FFmpeg through
 4.0.2 does not check for an empty audio packet, leading to an assertion
failure (CVE-2018-15822).

It also fixes mythbackend missing needed environment variables (mga#24104).

For other changes/fixes in this update, see the referenced Release Notes.");

  script_tag(name:"affected", value:"'hdhomerun, mythtv, mythtv-mythweb' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"hdhomerun", rpm:"hdhomerun~20180817~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hdhomerun-devel", rpm:"lib64hdhomerun-devel~20180817~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hdhomerun4", rpm:"lib64hdhomerun4~20180817~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth-devel", rpm:"lib64myth-devel~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth30", rpm:"lib64myth30~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64myth30", rpm:"lib64myth30~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdhomerun-devel", rpm:"libhdhomerun-devel~20180817~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhdhomerun4", rpm:"libhdhomerun4~20180817~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth-devel", rpm:"libmyth-devel~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth30", rpm:"libmyth30~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmyth30", rpm:"libmyth30~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv", rpm:"mythtv~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-backend", rpm:"mythtv-backend~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-common", rpm:"mythtv-common~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-doc", rpm:"mythtv-doc~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-frontend", rpm:"mythtv-frontend~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-mythweb", rpm:"mythtv-mythweb~30.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-archive", rpm:"mythtv-plugin-archive~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-browser", rpm:"mythtv-plugin-browser~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-gallery", rpm:"mythtv-plugin-gallery~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-game", rpm:"mythtv-plugin-game~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-music", rpm:"mythtv-plugin-music~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-netvision", rpm:"mythtv-plugin-netvision~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-news", rpm:"mythtv-plugin-news~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-weather", rpm:"mythtv-plugin-weather~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-plugin-zoneminder", rpm:"mythtv-plugin-zoneminder~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-setup", rpm:"mythtv-setup~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mythtv-themes-base", rpm:"mythtv-themes-base~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-MythTV", rpm:"perl-MythTV~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-mythtv", rpm:"php-mythtv~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mythtv", rpm:"python2-mythtv~30.0~20190121.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-mythtv", rpm:"python2-mythtv~30.0~20190121.1.mga6.tainted", rls:"MAGEIA6"))) {
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
