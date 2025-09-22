# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14246.1");
  script_cve_id("CVE-2013-2882", "CVE-2013-6639", "CVE-2013-6640", "CVE-2013-6668", "CVE-2014-0224", "CVE-2015-3193", "CVE-2015-3194", "CVE-2015-5380", "CVE-2015-7384", "CVE-2016-2086", "CVE-2016-2178", "CVE-2016-2183", "CVE-2016-2216", "CVE-2016-5172", "CVE-2016-5325", "CVE-2016-6304", "CVE-2016-6306", "CVE-2016-7052", "CVE-2016-7099", "CVE-2017-1000381", "CVE-2017-10686", "CVE-2017-11111", "CVE-2017-11499", "CVE-2017-14228", "CVE-2017-14849", "CVE-2017-14919", "CVE-2017-15896", "CVE-2017-15897", "CVE-2017-17810", "CVE-2017-17811", "CVE-2017-17812", "CVE-2017-17813", "CVE-2017-17814", "CVE-2017-17815", "CVE-2017-17816", "CVE-2017-17817", "CVE-2017-17818", "CVE-2017-17819", "CVE-2017-17820", "CVE-2017-18207", "CVE-2017-3735", "CVE-2017-3736", "CVE-2017-3738", "CVE-2018-0732", "CVE-2018-1000168", "CVE-2018-12115", "CVE-2018-12116", "CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123", "CVE-2018-20406", "CVE-2018-20852", "CVE-2018-7158", "CVE-2018-7159", "CVE-2018-7160", "CVE-2018-7161", "CVE-2018-7167", "CVE-2019-10160", "CVE-2019-11709", "CVE-2019-11710", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11714", "CVE-2019-11715", "CVE-2019-11716", "CVE-2019-11717", "CVE-2019-11718", "CVE-2019-11719", "CVE-2019-11720", "CVE-2019-11721", "CVE-2019-11723", "CVE-2019-11724", "CVE-2019-11725", "CVE-2019-11727", "CVE-2019-11728", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-11733", "CVE-2019-11735", "CVE-2019-11736", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11751", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-13173", "CVE-2019-15903", "CVE-2019-5010", "CVE-2019-5737", "CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518", "CVE-2019-9636", "CVE-2019-9811", "CVE-2019-9812", "CVE-2019-9947");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-02 18:47:22 +0000 (Wed, 02 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14246-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914246-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1029902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/104105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1447070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1447409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/744625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/744629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/935856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/937414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/947747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/948602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/955142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998743");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006249.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mozilla Firefox' package(s) announced via the SUSE-SU-2019:14246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update contains the Mozilla Firefox ESR 68.2 release.

Mozilla Firefox was updated to ESR 68.2 release:

* Enterprise: New administrative policies were added. More
 information and templates are available at the Policy
 Templates page.

* Various security fixes:
 MFSA 2019-33 (bsc#1154738)
 * CVE-2019-15903: Heap overflow in expat library in XML_GetCurrentLineNumber
 * CVE-2019-11757: Use-after-free when creating index updates in IndexedDB
 * CVE-2019-11758: Potentially exploitable crash due to 360 Total Security
 * CVE-2019-11759: Stack buffer overflow in HKDF output
 * CVE-2019-11760: Stack buffer overflow in WebRTC networking
 * CVE-2019-11761: Unintended access to a privileged JSONView object
 * CVE-2019-11762: document.domain-based origin isolation has same-origin- property violation
 * CVE-2019-11763: Incorrect HTML parsing results in XSS bypass technique
 * CVE-2019-11764: Memory safety bugs fixed in Firefox 70 and Firefox ESR 68.2

Other Issues resolved:

* [bsc#1104841] Newer versions of firefox have a dependency on
 GLIBCXX_3.4.20
* [bsc#1074235] MozillaFirefox: background tab crash reports sent
 inadvertently without user opt-in
* [bsc#1043008] Firefox hangs randomly when browsing and
 scrolling
* [bsc#1025108] Firefox stops loading page until mouse is moved
* [bsc#905528] Firefox malfunctions due to broken omni.ja
 archives");

  script_tag(name:"affected", value:"'Mozilla Firefox' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~68.2.0~78.51.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLED", rpm:"MozillaFirefox-branding-SLED~68~21.9.8", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~68.2.0~78.51.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~68.2.0~78.51.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-atk-lang", rpm:"firefox-atk-lang~2.26.1~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-lang", rpm:"firefox-gdk-pixbuf-lang~2.36.11~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-query-loaders", rpm:"firefox-gdk-pixbuf-query-loaders~2.36.11~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gdk-pixbuf-thumbnailer", rpm:"firefox-gdk-pixbuf-thumbnailer~2.36.11~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gio-branding-upstream", rpm:"firefox-gio-branding-upstream~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-lang", rpm:"firefox-glib2-lang~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-glib2-tools", rpm:"firefox-glib2-tools~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-branding-upstream", rpm:"firefox-gtk3-branding-upstream~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-data", rpm:"firefox-gtk3-data~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-amharic", rpm:"firefox-gtk3-immodule-amharic~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-inuktitut", rpm:"firefox-gtk3-immodule-inuktitut~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-multipress", rpm:"firefox-gtk3-immodule-multipress~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-thai", rpm:"firefox-gtk3-immodule-thai~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-vietnamese", rpm:"firefox-gtk3-immodule-vietnamese~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodule-xim", rpm:"firefox-gtk3-immodule-xim~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-immodules-tigrigna", rpm:"firefox-gtk3-immodules-tigrigna~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-lang", rpm:"firefox-gtk3-lang~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gtk3-tools", rpm:"firefox-gtk3-tools~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libatk-1_0-0", rpm:"firefox-libatk-1_0-0~2.26.1~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libcairo-gobject2", rpm:"firefox-libcairo-gobject2~1.15.10~2.13.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libcairo2", rpm:"firefox-libcairo2~1.15.10~2.13.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libffi4", rpm:"firefox-libffi4~5.3.1+r233831~14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libffi7", rpm:"firefox-libffi7~3.2.1.git259~2.3.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgdk_pixbuf-2_0-0", rpm:"firefox-libgdk_pixbuf-2_0-0~2.36.11~2.8.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libgtk-3-0", rpm:"firefox-libgtk-3-0~3.10.9~2.15.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libharfbuzz0", rpm:"firefox-libharfbuzz0~1.7.5~2.7.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-libpango-1_0-0", rpm:"firefox-libpango-1_0-0~1.40.14~2.7.4", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gio-2_0-0", rpm:"libfirefox-gio-2_0-0~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-glib-2_0-0", rpm:"libfirefox-glib-2_0-0~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gmodule-2_0-0", rpm:"libfirefox-gmodule-2_0-0~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gobject-2_0-0", rpm:"libfirefox-gobject-2_0-0~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfirefox-gthread-2_0-0", rpm:"libfirefox-gthread-2_0-0~2.54.3~2.14.7", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.21~29.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.21~29.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.21~29.6.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.45~38.9.3", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.45~38.9.3", rls:"SLES11.0SP4"))) {
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
