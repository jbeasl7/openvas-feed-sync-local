# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0275.1");
  script_cve_id("CVE-2024-7971");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-27 17:21:35 +0000 (Wed, 27 Nov 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0275-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TJMLQH7THP267EBNFZ3ECENLIIFCBW5H/");
  script_xref(name:"URL", value:"https://blogs.opera.com/desktop/changelog-for-113");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 113.0.5230.32

 * DNA-118250 Backport fix for CVE-2024-7971 from Chrome to
 Opera 113

- Changes in 113.0.5230.31

 * CHR-9819 Update Chromium on desktop-stable-127-5230 to
 127.0.6533.120
 * DNA-116113 Print window boxes have frames and text is not
 vertically centered
 * DNA-117467 Crash at static void views::Combobox::
 PaintIconAndText(class gfx::Canvas*)
 * DNA-117557 Fix detected dangling ptr in WorkspacesTabCycler
 ControllerIndexInCycleOrderTest.IndexInCyclingOrder
 * DNA-117721 [Lin] When I drag a tab out of the tab strip and
 drop it, it is not possible to do so without creating a
 new window.
 * DNA-117854 Pinned tab takes whole tab strip
 * DNA-117857 [Sync][Lost password] After profile error can't add
 passwords and sync can't display synced passwords
 * DNA-118215 Promote 113 to stable

- Complete Opera 113 changelog at:
 [link moved to references]");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~113.0.5230.32~lp156.2.17.1", rls:"openSUSELeap15.6"))) {
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
