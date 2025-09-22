# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0329.1");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0329-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0329-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/S7LDLB66CUPKJZCR47TCGM2A55KRG7OD/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230257");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'seamonkey' package(s) announced via the openSUSE-SU-2024:0329-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for seamonkey fixes the following issues:

update to SeaMonkey 2.53.19:

 * Cancel button in SeaMonkey bookmarking star ui not working bug
 1872623.
 * Remove OfflineAppCacheHelper.jsm copy from SeaMonkey and use the
 one in toolkit bug 1896292.
 * Remove obsolete registerFactoryLocation calls from cZ bug 1870930.
 * Remove needless implements='nsIDOMEventListener' and QI bug
 1611010.
 * Replace use of nsIStandardURL::Init bug 1864355.
 * Switch SeaMonkey website from hg.mozilla.org to heptapod. bug
 1870934.
 * Allow view-image to open a data: URI by setting a flag on the
 loadinfo bug 1877001.
 * Save-link-as feature should use the loading principal and context
 menu using nsIContentPolicy.TYPE_SAVE_AS_DOWNLOAD bug 1879726.
 * Use punycode in SeaMonkey JS bug 1864287.
 * Font lists in preferences are no longer grouped by font type, port
 asynchronous handling like Bug 1399206 bug 1437393.
 * SeaMonkey broken tab after undo closed tab with invalid protocol
 bug 1885748.
 * SeaMonkey session restore is missing the checkboxes in the Classic
 theme bug 1896174.
 * Implement about:credits on seamonkey-project.org website bug
 1898467.
 * Fix for the 0.0.0.0 day vulnerability oligo summary.
 * Link in update notification does not open Browser bug 1888364.
 * Update ReadExtensionPrefs in Preferences.cpp bug 1890196.
 * Add about:seamonkey page to SeaMonkey bug 1897801.
 * SeaMonkey 2.53.19 uses the same backend as Firefox and contains
 the relevant Firefox 60.8 security fixes.
 * SeaMonkey 2.53.19 shares most parts of the mail and news code with
 Thunderbird. Please read the Thunderbird 60.8.0 release notes for
 specific security fixes in this release.
 * Additional important security fixes up to Current Firefox 115.14
 and Thunderbird 115.14 ESR plus many enhancements have been
 backported. We will continue to enhance SeaMonkey security in
 subsequent 2.53.x beta and release versions as fast as we are able
 to.");

  script_tag(name:"affected", value:"'seamonkey' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~2.53.19~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~2.53.19~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"seamonkey-irc", rpm:"seamonkey-irc~2.53.19~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
