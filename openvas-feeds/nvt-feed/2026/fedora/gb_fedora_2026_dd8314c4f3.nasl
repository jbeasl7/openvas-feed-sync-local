# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10010083149941023");
  script_tag(name:"creation_date", value:"2026-02-03 04:37:30 +0000 (Tue, 03 Feb 2026)");
  script_version("2026-02-03T05:55:35+0000");
  script_tag(name:"last_modification", value:"2026-02-03 05:55:35 +0000 (Tue, 03 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-dd8314c4f3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-dd8314c4f3");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-dd8314c4f3");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334010");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openttd' package(s) announced via the FEDORA-2026-dd8314c4f3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"## 15.x

### 15.1 (2026-01-24)

- Fix #15088: When building a new train, the refit button state may be incorrect (#15162)
- Fix #15160: Incorrect company names displayed in load game window (#15161)
- Fix #15153: Wrong tile used to get bridge reservation overlay (#15154)
- Fix #15116: Old cargo/industry sets without cargo translation table broken (#15150)
- Fix: Possible crash converting company liveries in older savegames/scenarios (#15148)
- Fix: Allow infinite water to be (de)selected when loading heightmap (#15146)
- Fix: Tile suitability test for farm field no longer handled snow tiles (#15134)
- Fix #15131: Trees no longer spread on partially snowy tiles (#15133)
- Fix: Change tooltips to match change from checkboxes to switches (#15123)
- Fix: [Script] Potential out of bounds array/string slice indexes (#15106)
- Fix: [Script] Potential out of bounds indexed string access (#15106)
- Fix: [Script] Check if array sort function modified array (#15106)
- Fix #15069: World generation map edges GUI starts in an invalid state (#15082)
- Fix #15079: Incorrect dates shown on town cargo history graph (#15080)
- Fix #15067: Mark NewGRF settings as modified after moving by drag & drop (#15068)
- Fix: Incorrect error message for aqueducts reaching northern map borders (#14974)
- Fix: Standardize wording of GRF/NewGRF (#15059)
- Fix #15046: Crash on loading game due to invalid group parents (#15049)
- Fix: Disable_elrails handling with engines that use both RAIL and ELRL (#15045)
- Fix: [Fluidsynth] Read settings from system and user config files if available (#15044)
- Fix #15039: Name and version can disappear from content list (#15040)
- Fix #15026: Remove incorrect info from base sounds tooltip (#15029)
- Fix: [Script] Improve reporting of invalid GetAPIVersion return (#15015)
- Fix: [Script] Undefined behaviour after calling SwapList during iteration (#14805)");

  script_tag(name:"affected", value:"'openttd' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"openttd", rpm:"openttd~15.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openttd-debuginfo", rpm:"openttd-debuginfo~15.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openttd-debugsource", rpm:"openttd-debugsource~15.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openttd-docs", rpm:"openttd-docs~15.1~1.fc43", rls:"FC43"))) {
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
