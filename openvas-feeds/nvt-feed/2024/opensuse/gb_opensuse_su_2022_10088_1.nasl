# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833180");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-2163", "CVE-2022-2294", "CVE-2022-2295", "CVE-2022-2296", "CVE-2022-2477", "CVE-2022-2478", "CVE-2022-2479", "CVE-2022-2480", "CVE-2022-2481");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-04 17:11:39 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:32:11 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:10088-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10088-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/C6CFP4ALDNAUZ4ZAOFXUPGCPSV42N26M");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:10088-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:
  Opera was updated to 89.0.4447.71

  - CHR-8957 Update chromium on desktop-stable-103-4447 to 103.0.5060.134

  - DNA-100492 authPrivate.storeCredentials should work with running auth
         session

  - DNA-100649 Sign out from settings does not also sign out from
         auth

  - DNA-100653 VPN Badge popup  not working well with different page
         zoom being set in browser settings

  - DNA-100712 Wrong spacing on text to reset sync passphrase in settings

  - DNA-100799 VPN icon is pro on disconnected

  - DNA-100841 Remove Get Subscription and Get button from VPN pro settings

  - DNA-100883 Update missing translations from chromium

  - DNA-100899 Translation error in Turkish

  - DNA-100912 Unable to select pinboards when sync everything is enabled

  - DNA-100959 Use after move RecentSearchProvider::ExecuteWithDB

  - DNA-100960 Use after move
         CountryBlacklistServiceImpl::DownloadCountryBlacklist

  - DNA-100961 Use after move
         CategorizationDataCollection::Iterator::Iterator

  - DNA-100989 Crash at
         opera::EasyFileButton::SetThumbnail(gfx::ImageSkia const&amp )

  - The update to chromium 103.0.5060.134 fixes following issues:
       CVE-2022-2163, CVE-2022-2477, CVE-2022-2478, CVE-2022-2479
       CVE-2022-2480, CVE-2022-2481

  - Update to 89.0.4447.51

  - DNA-99538 Typed content of address bar shared between tabs

  - DNA-100418 Set 360 so as search engine in China

  - DNA-100629 Launch Auth login when enabling sync while logged in

  - DNA-100776 Popup is too long if there are no services available

  - Update to 89.0.4447.48

  - CHR-8940 Update chromium on desktop-stable-103-4447 to 103.0.5060.114

  - DNA-100247 Make it possible to display hint when tab scrolling gets
         triggered

  - DNA-100482 Shopping corner icon availability

  - DNA-100575 Add unique IDs to all web element in opera account popup

  - DNA-100625 Opera account popup appears too high on Linux

  - DNA-100627 Enable #snap-from-panel on all stream

  - DNA-100636 DCHECK at suggestion_item.cc(484)

  - DNA-100685 Fix crash when attaching to tab strip scroll buttons

  - DNA-100693 Enable Sticky Site sidebar item to have notification bubble

  - DNA-100698 [AdBlock] Unhandled Disconnect list category:
         'emailaggressive'

  - DNA-100716 Mistype Settings 'Enhanced address bar'

  - DNA-100732 Fix &amp amp  escaping in translated strings
      ...

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~89.0.4447.71~lp154.2.14.1", rls:"openSUSELeap15.4:NonFree"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~89.0.4447.71~lp154.2.14.1", rls:"openSUSELeap15.4:NonFree"))) {
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