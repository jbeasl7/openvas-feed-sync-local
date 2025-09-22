# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833159");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520", "CVE-2021-30541", "CVE-2021-30544", "CVE-2021-30545", "CVE-2021-30546", "CVE-2021-30547", "CVE-2021-30548", "CVE-2021-30549", "CVE-2021-30550", "CVE-2021-30551", "CVE-2021-30552", "CVE-2021-30553", "CVE-2021-30554", "CVE-2021-30555", "CVE-2021-30556", "CVE-2021-30557", "CVE-2021-30560", "CVE-2021-30561", "CVE-2021-30562", "CVE-2021-30563", "CVE-2021-30564", "CVE-2021-30590", "CVE-2021-30591", "CVE-2021-30592", "CVE-2021-30593", "CVE-2021-30594", "CVE-2021-30596", "CVE-2021-30597", "CVE-2021-30598", "CVE-2021-30599", "CVE-2021-30600", "CVE-2021-30601", "CVE-2021-30602", "CVE-2021-30603", "CVE-2021-30604", "CVE-2021-30606", "CVE-2021-30607", "CVE-2021-30608", "CVE-2021-30609", "CVE-2021-30610", "CVE-2021-30611", "CVE-2021-30612", "CVE-2021-30613", "CVE-2021-30614", "CVE-2021-30615", "CVE-2021-30616", "CVE-2021-30617", "CVE-2021-30618", "CVE-2021-30619", "CVE-2021-30620", "CVE-2021-30621", "CVE-2021-30622", "CVE-2021-30623", "CVE-2021-30624", "CVE-2021-30625", "CVE-2021-30626", "CVE-2021-30627", "CVE-2021-30628", "CVE-2021-30629", "CVE-2021-30630", "CVE-2021-30631", "CVE-2021-30632", "CVE-2021-30633", "CVE-2021-37974", "CVE-2021-37975", "CVE-2021-37976", "CVE-2021-37977", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980", "CVE-2021-37981", "CVE-2021-37982", "CVE-2021-37983", "CVE-2021-37984", "CVE-2021-37985", "CVE-2021-37986", "CVE-2021-37987", "CVE-2021-37988", "CVE-2021-37989", "CVE-2021-37990", "CVE-2021-37991", "CVE-2021-37992", "CVE-2021-37993", "CVE-2021-37994", "CVE-2021-37995", "CVE-2021-37996", "CVE-2021-37997", "CVE-2021-37998", "CVE-2021-37999", "CVE-2021-38001", "CVE-2021-38002", "CVE-2021-38003", "CVE-2021-38004", "CVE-2021-38005", "CVE-2021-38006", "CVE-2021-38007", "CVE-2021-38008", "CVE-2021-38009", "CVE-2021-38010", "CVE-2021-38011", "CVE-2021-38012", "CVE-2021-38013", "CVE-2021-38014", "CVE-2021-38015", "CVE-2021-38016", "CVE-2021-38017", "CVE-2021-38019", "CVE-2021-38020", "CVE-2021-38021", "CVE-2021-38022", "CVE-2021-4052", "CVE-2021-4053", "CVE-2021-4054", "CVE-2021-4055", "CVE-2021-4056", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4061", "CVE-2021-4062", "CVE-2021-4063", "CVE-2021-4064", "CVE-2021-4065", "CVE-2021-4066", "CVE-2021-4067", "CVE-2021-4068", "CVE-2021-4078", "CVE-2021-4079", "CVE-2021-4098", "CVE-2021-4099", "CVE-2021-4100", "CVE-2021-4101", "CVE-2021-4102", "CVE-2022-0096", "CVE-2022-0097", "CVE-2022-0098", "CVE-2022-0099", "CVE-2022-0100", "CVE-2022-0101", "CVE-2022-0102", "CVE-2022-0103", "CVE-2022-0104", "CVE-2022-0105", "CVE-2022-0106", "CVE-2022-0107", "CVE-2022-0108", "CVE-2022-0109", "CVE-2022-0110", "CVE-2022-0111", "CVE-2022-0112", "CVE-2022-0113", "CVE-2022-0114", "CVE-2022-0115", "CVE-2022-0116", "CVE-2022-0117", "CVE-2022-0118", "CVE-2022-0120", "CVE-2022-0289", "CVE-2022-0290", "CVE-2022-0291", "CVE-2022-0292", "CVE-2022-0293", "CVE-2022-0294", "CVE-2022-0295", "CVE-2022-0296", "CVE-2022-0297", "CVE-2022-0298", "CVE-2022-0300", "CVE-2022-0301", "CVE-2022-0302", "CVE-2022-0304", "CVE-2022-0305", "CVE-2022-0306", "CVE-2022-0307", "CVE-2022-0308", "CVE-2022-0309", "CVE-2022-0310", "CVE-2022-0311", "CVE-2022-0452", "CVE-2022-0453", "CVE-2022-0454", "CVE-2022-0455", "CVE-2022-0456", "CVE-2022-0457", "CVE-2022-0458", "CVE-2022-0459", "CVE-2022-0460", "CVE-2022-0461", "CVE-2022-0462", "CVE-2022-0463", "CVE-2022-0464", "CVE-2022-0465", "CVE-2022-0466", "CVE-2022-0467", "CVE-2022-0468", "CVE-2022-0469", "CVE-2022-0470", "CVE-2022-0603", "CVE-2022-0604", "CVE-2022-0605", "CVE-2022-0606", "CVE-2022-0607", "CVE-2022-0608", "CVE-2022-0609", "CVE-2022-0610", "CVE-2022-0789", "CVE-2022-0790", "CVE-2022-0791", "CVE-2022-0792", "CVE-2022-0793", "CVE-2022-0794", "CVE-2022-0795", "CVE-2022-0796", "CVE-2022-0797", "CVE-2022-0798", "CVE-2022-0799", "CVE-2022-0800", "CVE-2022-0801", "CVE-2022-0802", "CVE-2022-0803", "CVE-2022-0804", "CVE-2022-0805", "CVE-2022-0806", "CVE-2022-0807", "CVE-2022-0808", "CVE-2022-0809", "CVE-2022-1096");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 09:36:24 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:26:52 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:0110-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0110-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZOJPFVCOKYO6YUMKBJPTCF74IGAYK5K4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:0110-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:
  Update to 85.0.4341.28

  - CHR-8816 Update chromium on desktop-stable-99-4341 to 99.0.4844.84

  - DNA-98092 Crash at views::MenuItemView::GetMenuController()

  - DNA-98278 Translations for O85

  - DNA-98320 [Mac] Unable to delete recent search entries

  - DNA-98614 Show recent searches for non-BABE users

  - DNA-98615 Allow removal of recent searches

  - DNA-98616 Add recent searches to old BABE

  - DNA-98617 Make it possible to disable ad-blocker per-country

  - DNA-98651 Remove Instagram and Facebook Messenger in Russia

  - DNA-98653 Add flag #recent-searches

  - DNA-98696 smoketest
         PageInfoHistoryDataSourceTest.FormatTimestampString failing

  - DNA-98703 Port Chromium issue 1309225 to Opera Stable

  - The update to chromium 99.0.4844.84 fixes following issues: CVE-2022-1096

  - Changes in 85.0.4341.18

  - CHR-8789 Update chromium on desktop-stable-99-4341 to 99.0.4844.51

  - DNA-98059 [Linux] Crash at
         opera::FreedomSettingsImpl::IsBypassForDotlessDomainsEnabled

  - DNA-98349 [Linux] Crash at bluez::BluezDBusManager::Get()

  - DNA-98126 System crash dialog shown on macOS  = 10.15

  - DNA-98331 [Snap] Meme generator cropping / resizing broken

  - DNA-98394 Audio tab indicator set to 'muted' on videoconferencing sites

  - DNA-98481 Report errors in opauto_collector

  - The update to chromium 99.0.4844.51 fixes following issues:
       CVE-2022-0789, CVE-2022-0790, CVE-2022-0791, CVE-2022-0792,
       CVE-2022-0793, CVE-2022-0794, CVE-2022-0795, CVE-2022-0796,
       CVE-2022-0797, CVE-2022-0798, CVE-2022-0799, CVE-2022-0800,
       CVE-2022-0801, CVE-2022-0802, CVE-2022-0803, CVE-2022-0804,
       CVE-2022-0805, CVE-2022-0806, CVE-2022-0807, CVE-2022-0808, CVE-2022-0809

  - Changes in 85.0.4341.13

  - DNA-94119 Upgrade curl to 7.81.0

  - DNA-97849 [Mac monterey] System shortcut interfere with Operas
         `ToggleSearchInOpenTabs` shortcut

  - DNA-98204 Automatic popout happens when video is paused

  - DNA-98231 Shortcuts are blocked by displayed tab tooltip when
         triggered quickly after tooltip appears

  - DNA-98321 Add thinlto-cache warnings to suppression list

  - DNA-98395 Promote O85 to stable

  - DNA-98092 Crash at views::MenuItemView::GetMenuController()

  - DNA-98204 Automatic popout ha ...

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~85.0.4341.28~lp154.2.5.1", rls:"openSUSELeap15.4:NonFree"))) {
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
