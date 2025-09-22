# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833823");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-1350");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-15 17:36:33 +0000 (Wed, 15 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:19:16 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for liferea (openSUSE-SU-2023:0096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0096-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/U2XWO532L7BXCMKLBA5M4DP7HIU4NSO2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'liferea'
  package(s) announced via the openSUSE-SU-2023:0096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"liferea was updated to version 1.14.1:

     + Fix CVE-2023-1350 - Remote code execution on feed enrichment
       (boo#1209190).

     Update to version 1.14.0:

     + New 'Reader mode' preference that allows stripping all web content
     + Implement support for Webkits Intelligent Tracking Protection
     + New progress bar when loading websites
     + Youtube videos from media:video can be embedded now with a click on the
       video preview picture.
     + Changes to UserAgent handling: same UA is now used for both feed
       fetching and internal browsing.
     + New view mode 'Automatic' which switches between 'Normal' and 'Wide'
       mode based on the window proportions.
     + Liferea now supports the new GTK dark theme logic, where in the
       GTK/GNOME preferences you define whether you 'prefer' dark mode or light
       mode
     + Favicon discovery improvements: now detects all types of Apple Touch
       Icons, MS Tile Images and Safari Mask Icons
     + Increase size of stored favicons to 128x128px to improve icon quality in
       3-pane wide view.
     + Make several plugins support gettext
     + Allow multiple feed in same libnotify notification
     + Redesign of the update message in the status bar. It now shows a update
       counter of the feeds being in update.
     + You can now export a feed to XML file
     + Added an option to show news bins in reduced feed list
     + Added menu option to send item per mail
     + Default to https:// instead of http:// when user doesn't provide
       protocol on subscribing feed
     + Implement support for subscribing to LD+Json metadata listings e.g.
       concert or theater event listings
     + Implement support for subscribing to HTML5 websites
     + Support for media:description field of Youtube feeds
     + Improve HTML5 extraction: extract main tag if it exists and no article
       was found.
     + Execute feed pipe/filter commands asynchronously
     + Better explanation of feed update errors.
     + Added generic Google Reader API support (allows using FeedHQ, FreshRSS,
       Miniflux...)
     + Now allow converting TinyTinyRSS subscriptions to local subscriptions
     + New search folder rule to match podcasts
     + New search folder rule to match headline authors
     + New search folder rule to match subscription source
     + New search folder rule to match parent folder name
     + New search folder property that allows hiding read items
     + Now search folders are automatically rebuild when rules are changed
     + Added new plugin 'add-bookmark-site' that allows to configure a c ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'liferea' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"liferea", rpm:"liferea~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-debuginfo", rpm:"liferea-debuginfo~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-debugsource", rpm:"liferea-debugsource~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-lang", rpm:"liferea-lang~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea", rpm:"liferea~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-debuginfo", rpm:"liferea-debuginfo~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-debugsource", rpm:"liferea-debugsource~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liferea-lang", rpm:"liferea-lang~1.14.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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