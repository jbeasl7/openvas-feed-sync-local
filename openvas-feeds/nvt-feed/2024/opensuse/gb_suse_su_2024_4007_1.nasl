# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856731");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-47533", "CVE-2024-49502", "CVE-2024-49503");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-21 05:00:36 +0000 (Thu, 21 Nov 2024)");
  script_name("openSUSE: Security Advisory for bea (SUSE-SU-2024:4007-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4007-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/F7J5CURV4BWIXW57QFUUDVPJ7365VDJQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bea'
  package(s) announced via the SUSE-SU-2024:4007-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following issues:

  release-notes-susemanager-proxy:

  * Update to SUSE Manager 4.3.14

  * Bugs mentioned: bsc#1217003, bsc#1221505, bsc#1225619, bsc#1225960,
      bsc#1226917 bsc#1227606, bsc#1228036, bsc#1228345, bsc#1228851, bsc#1229079
      bsc#1229260, bsc#1229339

  ## Security update for SUSE Manager Server 4.3

  ### Description:

  This update fixes the following issues:

  release-notes-susemanager:

  * Update to SUSE Manager 4.3.14

  * Ubuntu 24.04 support as client

  * Product migration from RHEL and Clones to SUSE Liberty Linux

  * POS image templates now produce compressed images

  * Date format for API endpoints has been changed to ISO-8601 format

  * Security issues fixed: CVE-2024-47533, CVE-2024-49502, CVE-2024-49503

  * Bugs mentioned: bsc#1146701, bsc#1211899, bsc#1212985, bsc#1217003,
      bsc#1217338 bsc#1217978, bsc#1218090, bsc#1219450, bsc#1219645, bsc#1219887
      bsc#1221435, bsc#1221505, bsc#1223312, bsc#1223988, bsc#1224108 bsc#1224209,
      bsc#1225603, bsc#1225619, bsc#1225960, bsc#1226090 bsc#1226439, bsc#1226461,
      bsc#1226478, bsc#1226687, bsc#1226917 bsc#1227133, bsc#1227334, bsc#1227406,
      bsc#1227526, bsc#1227543 bsc#1227599, bsc#1227606, bsc#1227746, bsc#1228036,
      bsc#1228101 bsc#1228130, bsc#1228147, bsc#1228286, bsc#1228326, bsc#1228345
      bsc#1228412, bsc#1228545, bsc#1228638, bsc#1228851, bsc#1228945 bsc#1229079,
      bsc#1229178, bsc#1229260, bsc#1229339, bsc#1231332 bsc#1231852, bsc#1231922,
      bsc#1231900");

  script_tag(name:"affected", value:"'bea' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager-proxy", rpm:"release-notes-susemanager-proxy~4.3.14~150400.3.90.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"release-notes-susemanager", rpm:"release-notes-susemanager~4.3.14~150400.3.122.1", rls:"openSUSELeap15.4"))) {
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
