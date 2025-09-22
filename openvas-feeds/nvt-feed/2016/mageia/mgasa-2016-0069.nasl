# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131234");
  script_cve_id("CVE-2013-7447");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:40 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-11 16:28:51 +0000 (Fri, 11 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0069)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0069");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0069.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/10/2");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=799275");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/gtk+2.0/+bug/1540811");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17731");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17738");
  script_xref(name:"URL", value:"https://bugzilla.gnome.org/show_bug.cgi?id=703220");
  script_xref(name:"URL", value:"https://git.gnome.org/browse/gtk+/commit?id=894b1ae76a32720f4bb3d39cf460402e3ce331d6");
  script_xref(name:"URL", value:"https://github.com/mate-desktop/eom/issues/93");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk+2.0' package(s) announced via the MGASA-2016-0069 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gtk+2.0 packages fix security vulnerability:

Due to a logic error, an attempt to allocate a large block of memory
fails in gdk_cairo_set_source_pixbuf, leading to a crash of the app
that called it, for example, eom (CVE-2013-7447).");

  script_tag(name:"affected", value:"'gtk+2.0' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk+2.0", rpm:"gtk+2.0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail-devel", rpm:"lib64gail-devel~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gail18", rpm:"lib64gail18~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+-x11-2.0_0", rpm:"lib64gtk+-x11-2.0_0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+2.0-devel", rpm:"lib64gtk+2.0-devel~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk+2.0_0", rpm:"lib64gtk+2.0_0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gtk-gir2.0", rpm:"lib64gtk-gir2.0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail-devel", rpm:"libgail-devel~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgail18", rpm:"libgail18~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+-x11-2.0_0", rpm:"libgtk+-x11-2.0_0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+2.0-devel", rpm:"libgtk+2.0-devel~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk+2.0_0", rpm:"libgtk+2.0_0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-gir2.0", rpm:"libgtk-gir2.0~2.24.26~3.mga5", rls:"MAGEIA5"))) {
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
