# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02529.1");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6426", "CVE-2025-6427", "CVE-2025-6428", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-6431", "CVE-2025-6432", "CVE-2025-6433", "CVE-2025-6434", "CVE-2025-6435", "CVE-2025-6436", "CVE-2025-8027", "CVE-2025-8028", "CVE-2025-8029", "CVE-2025-8030", "CVE-2025-8031", "CVE-2025-8032", "CVE-2025-8033", "CVE-2025-8034", "CVE-2025-8035", "CVE-2025-8036", "CVE-2025-8037", "CVE-2025-8038", "CVE-2025-8039", "CVE-2025-8040");
  script_tag(name:"creation_date", value:"2025-07-28 04:26:42 +0000 (Mon, 28 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02529-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02529-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502529-1.html");
  script_xref(name:"URL", value:"http://github.com/tc39/proposal-error-capturestacktrace");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246664");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040938.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) announced via the SUSE-SU-2025:02529-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, MozillaFirefox-branding-SLE fixes the following issues:

MozillaFirefox is updated to the 140ESR series.

Firefox Extended Support Release 140.0esr ESR:

 * General

 - Reader View now has an enhanced Text and Layout menu with
 new options for character spacing, word spacing, and text
 alignment. These changes offer a more accessible reading
 experience.
 - Reader View now has a Theme menu with additional Contrast
 and Gray options. You can also select custom colors for text,
 background, and links from the Custom tab.
 - Firefox will now offer to temporarily remember when users
 grant permissions to sites (e.g. geolocation). Temporary
 permissions will be removed either after one hour or when the
 tab is closed.
 - Firefox now includes safeguards to prevent sites from
 abusing the history API by generating excessive history
 entries, which can make navigating with the back and forward
 buttons difficult by cluttering the history. This
 intervention ensures that such entries, unless interacted
 with by the user, are skipped when using the back and forward
 buttons.
 - Firefox now identifies all links in PDFs and turns them
 into hyperlinks.
 - You can now copy links from background tabs using the
 tabstrip context menu on macOS and Linux.
 - Users on macOS and Linux are now given the option to close
 only the current tab if the Quit keyboard shortcut is used
 while multiple tabs are open in the window. (bmo#None)

 * Sidebar and Tabs

 - You can now enable the updated Firefox sidebar in Settings
 > General > Browser Layout to quickly access multiple tools
 in one click, without leaving your main view. Sidebar tools
 include an AI chatbot of your choice, bookmarks, history, and
 tabs from devices you sync with your Mozilla account.
 - Keep a lot of tabs open? Try our new vertical tabs layout
 to quickly scan your list of tabs. With vertical tabs, your
 open and pinned tabs appear in the sidebar instead of along
 the top of the browser. To turn on vertical tabs, right-click
 on the toolbar near the top of the browser and select Turn on
 Vertical Tabs. If you've enabled the updated sidebar, you can
 also go to Customize sidebar and check Vertical tabs. Early
 testers report feeling more organized after using vertical
 tabs for a few days.
 - Stay productive and organized with less effort by grouping
 related tabs together. One simple way to create a group is to
 drag a tab onto another, pause until you see a highlight,
 then drop to create the group. Tab groups can be named,
 color-coded, and are always saved. You can close a group and
 reopen it later.
 - A tab preview is now displayed when hovering the mouse over
 background tabs, making it easier to locate the desired tab
 without needing to switch tabs.
 - The sidebar to view tabs from other devices can now be
 opened via the Tab overview menu.

 * Security & Privacy

 - HTTPS is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLE' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.1.0~150200.152.193.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~140~150200.9.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.1.0~150200.152.193.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.1.0~150200.152.193.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.1.0~150200.152.193.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules", rpm:"pipewire-modules~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.24~150300.4.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal", rpm:"xdg-desktop-portal~1.8.0~150200.5.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-devel", rpm:"xdg-desktop-portal-devel~1.8.0~150200.5.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-lang", rpm:"xdg-desktop-portal-lang~1.8.0~150200.5.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.1.0~150200.152.193.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~140~150200.9.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.1.0~150200.152.193.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.1.0~150200.152.193.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.1.0~150200.152.193.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire", rpm:"gstreamer-plugin-pipewire~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-lang", rpm:"pipewire-lang~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3", rpm:"pipewire-modules-0_3~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.49~150400.3.7.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal", rpm:"xdg-desktop-portal~1.10.1~150400.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-devel", rpm:"xdg-desktop-portal-devel~1.10.1~150400.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-lang", rpm:"xdg-desktop-portal-lang~1.10.1~150400.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~140.1.0~150200.152.193.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~140~150200.9.21.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~140.1.0~150200.152.193.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~140.1.0~150200.152.193.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~140.1.0~150200.152.193.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugin-pipewire", rpm:"gstreamer-plugin-pipewire~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpipewire-0_3-0", rpm:"libpipewire-0_3-0~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire", rpm:"pipewire~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-lang", rpm:"pipewire-lang~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-modules-0_3", rpm:"pipewire-modules-0_3~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-plugins-0_2", rpm:"pipewire-spa-plugins-0_2~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-spa-tools", rpm:"pipewire-spa-tools~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pipewire-tools", rpm:"pipewire-tools~0.3.64~150500.3.7.2", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal", rpm:"xdg-desktop-portal~1.16.0~150500.3.8.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-devel", rpm:"xdg-desktop-portal-devel~1.16.0~150500.3.8.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xdg-desktop-portal-lang", rpm:"xdg-desktop-portal-lang~1.16.0~150500.3.8.1", rls:"SLES15.0SP5"))) {
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
