# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833067");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2852", "CVE-2022-2853", "CVE-2022-2854", "CVE-2022-2855", "CVE-2022-2856", "CVE-2022-2857", "CVE-2022-2858", "CVE-2022-2859", "CVE-2022-2860", "CVE-2022-2861");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 18:58:39 +0000 (Wed, 28 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:10109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10109-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M3EKK4MLMDATPSNRXMTEBKLHWPMVGY2H");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:10109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 90.0.4480.54

  - CHR-8981 Update chromium on desktop-stable-104-4480 to 104.0.5112.102

  - DNA-98165 [buildsign] Whitelist Silent.nib when creating universal NI
         package on Mac

  - DNA-101309 Use base filename in PUT request when uploading files to
         buildbot

  - The update to chromium 104.0.5112.102 fixes following issues:
       CVE-2022-2852, CVE-2022-2854, CVE-2022-2855, CVE-2022-2857,
       CVE-2022-2858, CVE-2022-2853, CVE-2022-2856, CVE-2022-2859,
       CVE-2022-2860, CVE-2022-2861

  - Update to 90.0.4480.48

  - DNA-100835 AddressBarModelTestWithCategories.RefreshUnfiltered
         SuggestionsWhenPrefsChanged fails on beta stream

  - DNA-101171 Translations for O90

  - DNA-101216 Remove empty string from flow client_capabilities

  - DNA-101357 Promote O90 to Stable

  - DNA-101383 Revert DNA-101033

  - Complete Opera 90.0 changelog at:

  - Update to 89.0.4447.91

  - DNA-100673 Crash at void
         opera::ModalDialogBaseView::OnExtraButtonPressed (const class
          ui::Event&amp  const)

  - DNA-100915 [Sync Settings] Confirm your identity to enable encryption
         message flickers

  - DNA-100937 Missing links to ToS and Privacy Statement in launcher
         dialog when running installer with show-eula-window-on-start

  - DNA-101002 Make errors from webpack compilation appear in the log

  - DNA-101045 Popup contents are pushed outside of popup in 'Unprotected'
         VPN state

  - DNA-101076 Disabled Pinboards should have another color in Account
         popup

  - DNA-101086 Sync  Clicking Next on
         redirect anywhere

  - Update to 89.0.4447.83

  - DNA-99507 Badge deactivates on a basket page of the shop

  - DNA-99840 Add speed dials to start page

  - DNA-100127 Enable #enable-force-dark-from-settings on all streams

  - DNA-100233 [Settings] 'Sync everything' and 'Do not sync' unselects
         itself

  - DNA-100560 Add 'suggested speed dials' in the Google search box
         on the start page

  - DNA-100568 Fix icon in suggestions and update layout

  - DNA-100646 Add synchronization states to Opera account popup

  - DNA-100665 Create private API to open Account popup + allow rich hints

  - DNA-100668 Use a category based suggestion list to sort search box
         suggestions

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.4:NonFree.");

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

if(release == "openSUSELeap15.4:NonFree") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~90.0.4480.54~lp154.2.17.1", rls:"openSUSELeap15.4:NonFree"))) {
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
