# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0143");
  script_cve_id("CVE-2018-6560");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-28 16:12:29 +0000 (Wed, 28 Feb 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0143)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0143");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0143.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22562");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-02/msg00019.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'appstream-glib, bubblewrap, flatpak, flatpak-builder, ostree, xdg-desktop-portal, xdg-desktop-portal-gtk' package(s) announced via the MGASA-2018-0143 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated flatpak packages fix security vulnerability:

A sandbox escape in the flatpak dbus proxy in the authentication phase
(CVE-2018-6560).

The flatpak has been upgraded to the latest stable version, 0.10.3, which fixes
this issue. The bubblewrap, ostree, flatpak-builder, xdg-desktop-portal,
xdg-desktop-portal-gtk, and appstream-glib packages have also been upgraded to
support this updated.");

  script_tag(name:"affected", value:"'appstream-glib, bubblewrap, flatpak, flatpak-builder, ostree, xdg-desktop-portal, xdg-desktop-portal-gtk' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"appstream-glib", rpm:"appstream-glib~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"appstream-glib-i18n", rpm:"appstream-glib-i18n~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"appstream-util", rpm:"appstream-util~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bubblewrap", rpm:"bubblewrap~0.2.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-builder", rpm:"flatpak-builder~0.10.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64appstream-builder-gir1.0", rpm:"lib64appstream-builder-gir1.0~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64appstream-builder8", rpm:"lib64appstream-builder8~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64appstream-glib-devel", rpm:"lib64appstream-glib-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64appstream-glib-gir1.0", rpm:"lib64appstream-glib-gir1.0~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64appstream-glib8", rpm:"lib64appstream-glib8~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-devel", rpm:"lib64flatpak-devel~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak-gir1.0", rpm:"lib64flatpak-gir1.0~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flatpak0", rpm:"lib64flatpak0~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ostree-devel", rpm:"lib64ostree-devel~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ostree-gir1.0", rpm:"lib64ostree-gir1.0~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ostree1", rpm:"lib64ostree1~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libappstream-builder-gir1.0", rpm:"libappstream-builder-gir1.0~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libappstream-builder8", rpm:"libappstream-builder8~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libappstream-glib-devel", rpm:"libappstream-glib-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libappstream-glib-gir1.0", rpm:"libappstream-glib-gir1.0~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libappstream-glib8", rpm:"libappstream-glib8~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-devel", rpm:"libflatpak-devel~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak-gir1.0", rpm:"libflatpak-gir1.0~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~0.10.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-devel", rpm:"libostree-devel~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-gir1.0", rpm:"libostree-gir1.0~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree1", rpm:"libostree1~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ostree", rpm:"ostree~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ostree-grub2", rpm:"ostree-grub2~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ostree-tests", rpm:"ostree-tests~2018.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal", rpm:"xdg-desktop-portal~0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-devel", rpm:"xdg-desktop-portal-devel~0.9~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-gtk", rpm:"xdg-desktop-portal-gtk~0.9~1.mga6", rls:"MAGEIA6"))) {
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
