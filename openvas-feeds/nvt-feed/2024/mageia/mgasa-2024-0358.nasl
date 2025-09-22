# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0358");
  script_cve_id("CVE-2024-10573");
  script_tag(name:"creation_date", value:"2024-11-13 04:12:29 +0000 (Wed, 13 Nov 2024)");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-31 19:15:12 +0000 (Thu, 31 Oct 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0358)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0358");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0358.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33711");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/10/30/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/10/30/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/10/31/4");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/11/01/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mpg123' package(s) announced via the MGASA-2024-0358 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write flaw was found in mpg123 when handling crafted
streams. When decoding PCM, the libmpg123 may write past the end of a
heap-located buffer. Consequently, heap corruption may happen, and
arbitrary code execution may not be dismissed. The complexity required to
exploit this flaw is considered high as the payload must be validated by
the MPEG decoder and the PCM synth before execution. Additionally, to
successfully execute the attack, the user must scan through the stream,
making web live stream content (such as web radios) a very unlikely
attack vector. (CVE-2024-10573)");

  script_tag(name:"affected", value:"'mpg123' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mpg123-devel", rpm:"lib64mpg123-devel~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mpg123_0", rpm:"lib64mpg123_0~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpg123-devel", rpm:"libmpg123-devel~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmpg123_0", rpm:"libmpg123_0~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123", rpm:"mpg123~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-jack", rpm:"mpg123-jack~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-openal", rpm:"mpg123-openal~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-portaudio", rpm:"mpg123-portaudio~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-pulse", rpm:"mpg123-pulse~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-sdl", rpm:"mpg123-sdl~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpg123-sndio", rpm:"mpg123-sndio~1.31.3~1.1.mga9", rls:"MAGEIA9"))) {
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
