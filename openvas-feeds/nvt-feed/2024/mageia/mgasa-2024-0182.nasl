# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0182");
  script_cve_id("CVE-2022-48622");
  script_tag(name:"creation_date", value:"2024-05-22 04:11:38 +0000 (Wed, 22 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:53:45 +0000 (Fri, 02 Feb 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0182)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0182");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0182.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33223");
  script_xref(name:"URL", value:"https://gitlab.gnome.org/GNOME/gdk-pixbuf/-/issues/202");
  script_xref(name:"URL", value:"https://lwn.net/Articles/973904/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf2.0' package(s) announced via the MGASA-2024-0182 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In GNOME GdkPixbuf (aka gdk-pixbuf) through 2.42.10, the ANI (Windows
animated cursor) decoder encounters heap memory corruption (in
ani_load_chunk in io-ani.c) when parsing chunks in a crafted .ani file.
A crafted file could allow an attacker to overwrite heap metadata,
leading to a denial of service or code execution attack. This occurs in
gdk_pixbuf_set_option() in gdk-pixbuf.c.");

  script_tag(name:"affected", value:"'gdk-pixbuf2.0' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf2.0", rpm:"gdk-pixbuf2.0~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf-gir2.0", rpm:"lib64gdk_pixbuf-gir2.0~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0-devel", rpm:"lib64gdk_pixbuf2.0-devel~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gdk_pixbuf2.0_0", rpm:"lib64gdk_pixbuf2.0_0~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-gir2.0", rpm:"libgdk_pixbuf-gir2.0~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0-devel", rpm:"libgdk_pixbuf2.0-devel~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf2.0_0", rpm:"libgdk_pixbuf2.0_0~2.42.10~2.1.mga9", rls:"MAGEIA9"))) {
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
