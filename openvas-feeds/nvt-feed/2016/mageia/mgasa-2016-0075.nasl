# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131228");
  script_cve_id("CVE-2013-7447");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:35 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-11 16:28:51 +0000 (Fri, 11 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0075");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0075.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/02/10/6");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17747");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gambas3' package(s) announced via the MGASA-2016-0075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated gambas3 packages fix security vulnerability:

Due to a logic error, an attempt to allocate a large block of memory
fails in gt_cairo_create_surface, leading to a crash of gambas3
(CVE-2013-7447).");

  script_tag(name:"affected", value:"'gambas3' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gambas3", rpm:"gambas3~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-devel", rpm:"gambas3-devel~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-examples", rpm:"gambas3-examples~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-args", rpm:"gambas3-gb-args~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-cairo", rpm:"gambas3-gb-cairo~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-chart", rpm:"gambas3-gb-chart~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-clipper", rpm:"gambas3-gb-clipper~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-complex", rpm:"gambas3-gb-complex~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-compress", rpm:"gambas3-gb-compress~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-crypt", rpm:"gambas3-gb-crypt~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-data", rpm:"gambas3-gb-data~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db", rpm:"gambas3-gb-db~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db-form", rpm:"gambas3-gb-db-form~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db-mysql", rpm:"gambas3-gb-db-mysql~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db-odbc", rpm:"gambas3-gb-db-odbc~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db-postgresql", rpm:"gambas3-gb-db-postgresql~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-db-sqlite3", rpm:"gambas3-gb-db-sqlite3~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-dbus", rpm:"gambas3-gb-dbus~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-desktop", rpm:"gambas3-gb-desktop~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-eval-highlight", rpm:"gambas3-gb-eval-highlight~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-form", rpm:"gambas3-gb-form~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-form-dialog", rpm:"gambas3-gb-form-dialog~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-form-mdi", rpm:"gambas3-gb-form-mdi~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-form-stock", rpm:"gambas3-gb-form-stock~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-geom", rpm:"gambas3-gb-geom~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-gmp", rpm:"gambas3-gb-gmp~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-gsl", rpm:"gambas3-gb-gsl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-gtk", rpm:"gambas3-gb-gtk~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-gui", rpm:"gambas3-gb-gui~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-httpd", rpm:"gambas3-gb-httpd~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-image", rpm:"gambas3-gb-image~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-image-effect", rpm:"gambas3-gb-image-effect~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-image-imlib", rpm:"gambas3-gb-image-imlib~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-image-io", rpm:"gambas3-gb-image-io~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-inotify", rpm:"gambas3-gb-inotify~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-jit", rpm:"gambas3-gb-jit~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-libxml", rpm:"gambas3-gb-libxml~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-logging", rpm:"gambas3-gb-logging~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-map", rpm:"gambas3-gb-map~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-markdown", rpm:"gambas3-gb-markdown~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-media", rpm:"gambas3-gb-media~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-memcached", rpm:"gambas3-gb-memcached~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-mime", rpm:"gambas3-gb-mime~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-mysql", rpm:"gambas3-gb-mysql~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-ncurses", rpm:"gambas3-gb-ncurses~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-net", rpm:"gambas3-gb-net~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-net-curl", rpm:"gambas3-gb-net-curl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-net-pop3", rpm:"gambas3-gb-net-pop3~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-net-smtp", rpm:"gambas3-gb-net-smtp~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-opengl", rpm:"gambas3-gb-opengl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-opengl-glsl", rpm:"gambas3-gb-opengl-glsl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-opengl-glu", rpm:"gambas3-gb-opengl-glu~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-opengl-sge", rpm:"gambas3-gb-opengl-sge~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-openssl", rpm:"gambas3-gb-openssl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-option", rpm:"gambas3-gb-option~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-pcre", rpm:"gambas3-gb-pcre~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-pdf", rpm:"gambas3-gb-pdf~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-qt4", rpm:"gambas3-gb-qt4~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-qt4-ext", rpm:"gambas3-gb-qt4-ext~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-qt4-opengl", rpm:"gambas3-gb-qt4-opengl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-qt4-webkit", rpm:"gambas3-gb-qt4-webkit~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-report", rpm:"gambas3-gb-report~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-sdl", rpm:"gambas3-gb-sdl~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-sdl-sound", rpm:"gambas3-gb-sdl-sound~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-settings", rpm:"gambas3-gb-settings~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-signal", rpm:"gambas3-gb-signal~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-v4l", rpm:"gambas3-gb-v4l~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-vb", rpm:"gambas3-gb-vb~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-web", rpm:"gambas3-gb-web~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-xml", rpm:"gambas3-gb-xml~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-xml-html", rpm:"gambas3-gb-xml-html~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-xml-rpc", rpm:"gambas3-gb-xml-rpc~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-gb-xml-xslt", rpm:"gambas3-gb-xml-xslt~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-ide", rpm:"gambas3-ide~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-runtime", rpm:"gambas3-runtime~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gambas3-script", rpm:"gambas3-script~3.6.2~4.2.mga5", rls:"MAGEIA5"))) {
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
