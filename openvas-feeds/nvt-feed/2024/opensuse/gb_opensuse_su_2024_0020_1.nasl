# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833852");
  script_cve_id("CVE-2023-6508", "CVE-2023-6509", "CVE-2023-6510", "CVE-2023-6511", "CVE-2023-6512", "CVE-2023-6702", "CVE-2023-6703", "CVE-2023-6704", "CVE-2023-6705", "CVE-2023-6706", "CVE-2023-6707", "CVE-2023-7024", "CVE-2024-0222", "CVE-2024-0223", "CVE-2024-0224", "CVE-2024-0225", "CVE-2024-0333");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:31 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:41:43 +0000 (Mon, 08 Jan 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0020-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2KWUFI7NWEEY53YIAANSM3OSYVP7LTDM/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218719");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2024:0020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 120.0.6099.216 (boo#1217839, boo#1218048, boo#1218302,
 boo#1218533, boo#1218719)

 * CVE-2024-0333: Insufficient data validation in Extensions
 * CVE-2024-0222: Use after free in ANGLE
 * CVE-2024-0223: Heap buffer overflow in ANGLE
 * CVE-2024-0224: Use after free in WebAudio
 * CVE-2024-0225: Use after free in WebGPU
 * CVE-2023-7024: Heap buffer overflow in WebRTC
 * CVE-2023-6702: Type Confusion in V8
 * CVE-2023-6703: Use after free in Blink
 * CVE-2023-6704: Use after free in libavif (boo#1218303)
 * CVE-2023-6705: Use after free in WebRTC
 * CVE-2023-6706: Use after free in FedCM
 * CVE-2023-6707: Use after free in CSS
 * CVE-2023-6508: Use after free in Media Stream
 * CVE-2023-6509: Use after free in Side Panel Search
 * CVE-2023-6510: Use after free in Media Capture
 * CVE-2023-6511: Inappropriate implementation in Autofill
 * CVE-2023-6512: Inappropriate implementation in Web Browser UI");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~120.0.6099.216~bp155.2.64.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~120.0.6099.216~bp155.2.64.1", rls:"openSUSELeap15.5"))) {
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
