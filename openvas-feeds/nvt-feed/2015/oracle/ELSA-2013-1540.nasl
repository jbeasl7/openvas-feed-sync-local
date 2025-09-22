# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123532");
  script_cve_id("CVE-2013-4166");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:09 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-10 18:47:00 +0000 (Mon, 10 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2013-1540)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1540");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1540.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cheese, control-center, ekiga, evolution, evolution-data-server, evolution-exchange, evolution-mapi, gnome-panel, gnome-python2-desktop, gtkhtml3, libgdata, nautilus-sendto, openchange, pidgin, planner, totem' package(s) announced via the ELSA-2013-1540 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cheese
[2.28.1-8]
- Rebuild against newer evolution-data-server.
Resolves: #973276

control-center
[2.28.1-39]
- Rebuild against newer evolution-data-server.
Resolves: #973279

ekiga
[3.2.6-4]
- Rebuild against newer evolution-data-server.
- Add patch to build break (include where needed)
Resolves: #973281

evolution
[2.32.3-30.el6]
- Update patch for RH bug #975409 (Custom message in alarm notification)
- Add patch for RH bug #1014743 (Use system timezone has no effect)
- Add patch for RH bug #1014677 (Search filter persists when changing folders)

[2.32.3-29.el6]
- Add patch for RH bug #1013543 (Freeze during migration of pre-2.24 mails)

[2.32.3-28.el6]
- Add patch for RH bug #1012399 (Fails to display task mail attachment)
- Bump evolution-data-server version requirement (for RH bug #1009426)

[2.32.3-27.el6]
- Add patch for RH bug #1009517 (Be aware of 'no-alarm-after-start' calendar capability)

[2.32.3-26.el6]
- Add patch for RH bug #1006764 (Plugin actions not updated)

[2.32.3-25.el6]
- Add patch for RH bug #1003578 (Update actions on search execute)

[2.32.3-24.el6]
- Update translations for the Exchange Web Services advertisement

[2.32.3-23.el6]
- Build evolution-devel-docs for noarch only

[2.32.3-22.el6]
- Add a devel-docs subpackage and do not ship evolution-settings (RH bug #1000323)

[2.32.3-21.el6]
- Remove bogofilter plugin from el6 (missed previous removal during rebase)

[2.32.3-20.el6]
- Update bn_IN translation

[2.32.3-19.el6]
- Show a one-time dialog on upgrade advertising Exchange Web Services.

[2.32.3-18.el6]
- Update translation patch

[2.32.3-17.el6]
- Add patch for icons in a message list Wide View

[2.32.3-16.el6]
- Add patch for translation updates

[2.32.3-15.el6]
- Update patch for RH bug #949610 (Avoid runtime warnings caused by async load)

[2.32.3-14.el6]
- Update patch for RH bug #975409 (Custom message in alarm notification)
- Add patch for RH bug #985528 (Multiple contacts remove confuses view)

[2.32.3-13.el6]
- Obsolete evolution-conduits, thus an update can be done, when it's installed
- Add patch for RH bug #981313 (a11y in the Contacts' minicard view)
- Add patch for RH bug #981257 (Save changes in addressbook backend's ensure_sources)

[2.32.3-12.el6]
- Add patch for use-after-free memory in mail account editor found by valgrind

[2.32.3-11.el6]
- Add patch for RH bug #978525 (CamelSession left with unset network-available)

[2.32.3-10.el6]
- Add patch for RH bug #956510 (Alarm notify crash and other related fixes in alarm notify)
- Update patch for RH bug #977292 (Close also evolution-alarm-notify process)

[2.32.3-9.el6]
- Add patch for RH bug #624851 (Select S/MIME encryption certificate)
- Add patch for RH bug #628174 (Copy/Paste text in calendar views)
- Add patch for RH bug #971496 (Notify user about question dialogs)
- Add patch for RH bug #977292 (--force-shutdown closes also factories)

[2.32.3-8.el6]
- Add patch ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cheese, control-center, ekiga, evolution, evolution-data-server, evolution-exchange, evolution-mapi, gnome-panel, gnome-python2-desktop, gtkhtml3, libgdata, nautilus-sendto, openchange, pidgin, planner, totem' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"cheese", rpm:"cheese~2.28.1~8.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"control-center", rpm:"control-center~2.28.1~39.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"control-center-devel", rpm:"control-center-devel~2.28.1~39.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"control-center-extra", rpm:"control-center-extra~2.28.1~39.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"control-center-filesystem", rpm:"control-center-filesystem~2.28.1~39.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ekiga", rpm:"ekiga~3.2.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution", rpm:"evolution~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server", rpm:"evolution-data-server~2.32.3~18.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-devel", rpm:"evolution-data-server-devel~2.32.3~18.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-data-server-doc", rpm:"evolution-data-server-doc~2.32.3~18.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-devel", rpm:"evolution-devel~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-devel-docs", rpm:"evolution-devel-docs~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-exchange", rpm:"evolution-exchange~2.32.3~16.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-help", rpm:"evolution-help~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-mapi", rpm:"evolution-mapi~0.32.2~12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-mapi-devel", rpm:"evolution-mapi-devel~0.32.2~12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-perl", rpm:"evolution-perl~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-pst", rpm:"evolution-pst~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evolution-spamassassin", rpm:"evolution-spamassassin~2.32.3~30.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"finch", rpm:"finch~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-panel", rpm:"gnome-panel~2.30.2~15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-panel-devel", rpm:"gnome-panel-devel~2.30.2~15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-panel-libs", rpm:"gnome-panel-libs~2.30.2~15.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-applet", rpm:"gnome-python2-applet~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-brasero", rpm:"gnome-python2-brasero~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-bugbuddy", rpm:"gnome-python2-bugbuddy~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-desktop", rpm:"gnome-python2-desktop~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-evince", rpm:"gnome-python2-evince~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-evolution", rpm:"gnome-python2-evolution~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-gnomedesktop", rpm:"gnome-python2-gnomedesktop~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-gnomekeyring", rpm:"gnome-python2-gnomekeyring~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-gnomeprint", rpm:"gnome-python2-gnomeprint~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-gtksourceview", rpm:"gnome-python2-gtksourceview~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-libgtop2", rpm:"gnome-python2-libgtop2~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-libwnck", rpm:"gnome-python2-libwnck~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-metacity", rpm:"gnome-python2-metacity~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-rsvg", rpm:"gnome-python2-rsvg~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-python2-totem", rpm:"gnome-python2-totem~2.28.0~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtkhtml3", rpm:"gtkhtml3~3.32.2~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtkhtml3-devel", rpm:"gtkhtml3-devel~3.32.2~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdata", rpm:"libgdata~0.6.4~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdata-devel", rpm:"libgdata-devel~0.6.4~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-sendto", rpm:"nautilus-sendto~2.28.2~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-sendto-devel", rpm:"nautilus-sendto-devel~2.28.2~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange", rpm:"openchange~1.0~6.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-client", rpm:"openchange-client~1.0~6.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-devel", rpm:"openchange-devel~1.0~6.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openchange-devel-docs", rpm:"openchange-devel-docs~1.0~6.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-docs", rpm:"pidgin-docs~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.7.9~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"planner", rpm:"planner~0.14.4~10.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"planner-devel", rpm:"planner-devel~0.14.4~10.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"planner-eds", rpm:"planner-eds~0.14.4~10.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem", rpm:"totem~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-devel", rpm:"totem-devel~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-jamendo", rpm:"totem-jamendo~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-mozplugin", rpm:"totem-mozplugin~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-nautilus", rpm:"totem-nautilus~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-upnp", rpm:"totem-upnp~2.28.6~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"totem-youtube", rpm:"totem-youtube~2.28.6~4.el6", rls:"OracleLinux6"))) {
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
