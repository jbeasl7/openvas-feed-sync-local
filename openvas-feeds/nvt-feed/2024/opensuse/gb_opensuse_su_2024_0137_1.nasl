# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856155");
  script_cve_id("CVE-2024-5157", "CVE-2024-5158", "CVE-2024-5159", "CVE-2024-5160");
  script_tag(name:"creation_date", value:"2024-05-24 01:01:47 +0000 (Fri, 24 May 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 17:14:27 +0000 (Fri, 20 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0137-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0137-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OUHQT3H7SVUMWPOBHPV62RCKTAJROHUB/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224818");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0137-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 125.0.6422.76 (boo#1224818)
 * CVE-2024-5157: Use after free in Scheduling
 * CVE-2024-5158: Type Confusion in V8
 * CVE-2024-5159: Heap buffer overflow in ANGLE
 * CVE-2024-5160: Heap buffer overflow in Dawn
 * Various fixes from internal audits, fuzzing and other initiatives");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~125.0.6422.76~bp155.2.85.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~125.0.6422.76~bp155.2.85.2", rls:"openSUSELeap15.5"))) {
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
