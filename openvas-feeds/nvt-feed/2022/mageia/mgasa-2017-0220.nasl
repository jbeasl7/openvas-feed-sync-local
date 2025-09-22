# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0220");
  script_cve_id("CVE-2017-9122", "CVE-2017-9123", "CVE-2017-9124", "CVE-2017-9125", "CVE-2017-9126", "CVE-2017-9127", "CVE-2017-9128");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-15 15:48:49 +0000 (Thu, 15 Jun 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0220");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0220.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21196");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-07/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libquicktime' package(s) announced via the MGASA-2017-0220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A DoS in quicktime_read_moov function in moov.c via acrafted mp4 file
was fixed (CVE-2017-9122).

An invalid memory read in lqt_frame_duration via a crafted mp4 file was
fixed (CVE-2017-9123).

A NULL pointer dereference in quicktime_match_32 via a crafted mp4 file
was fixed (CVE-2017-9124).

A DoS in lqt_frame_duration function in lqt_quicktime.c via crafted mp4
file was fixed (CVE-2017-9125).

A heap-based buffer overflow in quicktime_read_dref_table via a crafted
mp4 file was fixed (CVE-2017-9126).

A heap-based buffer overflow in quicktime_user_atoms_read_atom via a
crafted mp4 file was fixed (CVE-2017-9127).

A heap-based buffer over-read in quicktime_video_width via a crafted mp4
file was fixed (CVE-2017-9128).");

  script_tag(name:"affected", value:"'libquicktime' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime-devel", rpm:"lib64quicktime-devel~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime0", rpm:"lib64quicktime0~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime", rpm:"libquicktime~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-devel", rpm:"libquicktime-devel~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-dv", rpm:"libquicktime-dv~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-progs", rpm:"libquicktime-progs~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~10.2.mga5", rls:"MAGEIA5"))) {
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
