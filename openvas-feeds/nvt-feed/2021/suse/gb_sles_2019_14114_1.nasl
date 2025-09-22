# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14114.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14114-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914114-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137338");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005661.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) announced via the SUSE-SU-2019:14114-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains Mozilla Firefox 60.7ESR.

It brings lots of security fixes and other improvements.

It also includes new additional helper libraries to allow Firefox to run on SUSE Linux Enterprise 11.");

  script_tag(name:"affected", value:"'MozillaFirefox, mozilla-nspr, mozilla-nss' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.7.0esr~78.40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~60~21.6.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.7.0esr~78.40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.7.0esr~78.40.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-at-spi2-core", rpm:"firefox-at-spi2-core~2.10.2~2.6.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-at-spi2-core-lang", rpm:"firefox-at-spi2-core-lang~2.10.2~2.6.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-atk-lang", rpm:"firefox-atk-lang~2.26.1~2.5.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-dbus-1-glib", rpm:"firefox-dbus-1-glib~0.76~34.2.4.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-lang", rpm:"firefox-gdk-pixbuf-lang~2.36.11~2.5.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-query-loaders", rpm:"firefox-gdk-pixbuf-query-loaders~2.36.11~2.5.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-thumbnailer", rpm:"firefox-gdk-pixbuf-thumbnailer~2.36.11~2.5.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gio-branding-upstream", rpm:"firefox-gio-branding-upstream~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-lang", rpm:"firefox-glib2-lang~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-tools", rpm:"firefox-glib2-tools~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-branding-upstream", rpm:"firefox-gtk3-branding-upstream~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-data", rpm:"firefox-gtk3-data~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-amharic", rpm:"firefox-gtk3-immodule-amharic~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-inuktitut", rpm:"firefox-gtk3-immodule-inuktitut~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-multipress", rpm:"firefox-gtk3-immodule-multipress~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-thai", rpm:"firefox-gtk3-immodule-thai~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-vietnamese", rpm:"firefox-gtk3-immodule-vietnamese~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-xim", rpm:"firefox-gtk3-immodule-xim~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodules-tigrigna", rpm:"firefox-gtk3-immodules-tigrigna~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-lang", rpm:"firefox-gtk3-lang~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-tools", rpm:"firefox-gtk3-tools~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libatk-1_0-0", rpm:"firefox-libatk-1_0-0~2.26.1~2.5.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libatk-bridge-2_0-0", rpm:"firefox-libatk-bridge-2_0-0~2.10.2~2.6.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libatspi0", rpm:"firefox-libatspi0~2.10.2~2.6.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libcairo-gobject2", rpm:"firefox-libcairo-gobject2~1.15.10~2.8.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libcairo2", rpm:"firefox-libcairo2~1.15.10~2.8.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libfreetype6", rpm:"firefox-libfreetype6~2.9~2.4.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgcc_s1", rpm:"firefox-libgcc_s1~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgdk_pixbuf-2_0-0", rpm:"firefox-libgdk_pixbuf-2_0-0~2.36.11~2.5.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgtk-3-0", rpm:"firefox-libgtk-3-0~3.10.9~2.8.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libharfbuzz0", rpm:"firefox-libharfbuzz0~1.7.5~2.4.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libpango-1_0-0", rpm:"firefox-libpango-1_0-0~1.40.14~2.4.5", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libpixman-1-0", rpm:"firefox-libpixman-1-0~0.34.0~2.5.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libstdc++6", rpm:"firefox-libstdc++6~5.3.1+r233831~10.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gio-2_0-0", rpm:"libfirefox-gio-2_0-0~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-glib-2_0-0", rpm:"libfirefox-glib-2_0-0~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gmodule-2_0-0", rpm:"libfirefox-gmodule-2_0-0~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gobject-2_0-0", rpm:"libfirefox-gobject-2_0-0~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gthread-2_0-0", rpm:"libfirefox-gthread-2_0-0~2.54.3~2.4.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.20~29.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.20~29.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.20~29.3.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.41.1~38.6.1", rls:"SLES11.0SP4"))) {
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
