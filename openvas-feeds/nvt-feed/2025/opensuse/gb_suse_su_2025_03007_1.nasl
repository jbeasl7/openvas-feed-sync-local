# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03007.1");
  script_cve_id("CVE-2025-9179", "CVE-2025-9180", "CVE-2025-9181", "CVE-2025-9182", "CVE-2025-9184", "CVE-2025-9185");
  script_tag(name:"creation_date", value:"2025-09-01 04:12:42 +0000 (Mon, 01 Sep 2025)");
  script_version("2025-09-01T05:39:44+0000");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 14:15:43 +0000 (Thu, 21 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03007-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503007-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248162");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041411.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:03007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Updated to Mozilla Thunderbird 140.2 MFSA 2025-72 (bsc#1248162):
 * CVE-2025-9179: Sandbox escape due to invalid pointer in the Audio/Video: GMP
 component
 * CVE-2025-9180: Same-origin policy bypass in the Graphics: Canvas2D component
 * CVE-2025-9181: Uninitialized memory in the JavaScript Engine component
 * CVE-2025-9182: Denial-of-service due to out-of-memory in the Graphics:
 WebRender component
 * CVE-2025-9184: Memory safety bugs fixed in Firefox ESR 140.2, Thunderbird
 ESR 140.2, Firefox 142 and Thunderbird 142
 * CVE-2025-9185: Memory safety bugs fixed in Firefox ESR 115.27, Firefox ESR
 128.14, Thunderbird ESR 128.14, Firefox ESR 140.2,
 Thunderbird ESR 140.2, Firefox 142 and Thunderbird 142

Other fixes:
 * Users were unable to use Fastmail calendars due to
 missing OAuth settings
 * Account setup error handling was broken for Account
 hub
 * Menu bar was hidden after updating from 128esr to
 140esr");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~140.2.0~150200.8.236.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~140.2.0~150200.8.236.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~140.2.0~150200.8.236.1", rls:"openSUSELeap15.6"))) {
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
