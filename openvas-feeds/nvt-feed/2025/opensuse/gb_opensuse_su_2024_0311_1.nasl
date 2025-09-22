# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2024.0311.1");
  script_cve_id("CVE-2024-8904", "CVE-2024-8905", "CVE-2024-8906", "CVE-2024-8907", "CVE-2024-8908", "CVE-2024-8909");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-02 17:33:01 +0000 (Thu, 02 Jan 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0311-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/O7WDMIQP5NDZYKLBCM5CDD2MLYLDW5B3/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230678");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

Chromium 129.0.6668.58 (stable released 2024-09-17) (boo#1230678)

 * CVE-2024-8904: Type Confusion in V8
 * CVE-2024-8905: Inappropriate implementation in V8
 * CVE-2024-8906: Incorrect security UI in Downloads
 * CVE-2024-8907: Insufficient data validation in Omnibox
 * CVE-2024-8908: Inappropriate implementation in Autofill
 * CVE-2024-8909: Inappropriate implementation in UI");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~129.0.6668.58~bp156.2.29.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~129.0.6668.58~bp156.2.29.2", rls:"openSUSELeap15.6"))) {
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
