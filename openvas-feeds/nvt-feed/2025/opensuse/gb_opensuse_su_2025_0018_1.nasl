# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0018.1");
  script_cve_id("CVE-2025-0434", "CVE-2025-0435", "CVE-2025-0436", "CVE-2025-0437", "CVE-2025-0438", "CVE-2025-0439", "CVE-2025-0440", "CVE-2025-0441", "CVE-2025-0442", "CVE-2025-0443", "CVE-2025-0446", "CVE-2025-0447", "CVE-2025-0448");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-16 20:35:01 +0000 (Thu, 16 Jan 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0018-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MFF3YLZEHLO6D6YWHQPJAEDFFFBY7ESE/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235892");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2025:0018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 132.0.6834.83
 (stable released 2024-01-14) (boo#1235892)
 * CVE-2025-0434: Out of bounds memory access in V8
 * CVE-2025-0435: Inappropriate implementation in Navigation
 * CVE-2025-0436: Integer overflow in Skia
 * CVE-2025-0437: Out of bounds read in Metrics
 * CVE-2025-0438: Stack buffer overflow in Tracing
 * CVE-2025-0439: Race in Frames
 * CVE-2025-0440: Inappropriate implementation in Fullscreen
 * CVE-2025-0441: Inappropriate implementation in Fenced Frames
 * CVE-2025-0442: Inappropriate implementation in Payments
 * CVE-2025-0443: Insufficient data validation in Extensions
 * CVE-2025-0446: Inappropriate implementation in Extensions
 * CVE-2025-0447: Inappropriate implementation in Navigation
 * CVE-2025-0448: Inappropriate implementation in Compositing
- update esbuild to 0.24.0
 - drop old tarball
 - use upstream release tarball for 0.24.0
 - add vendor tarball for golang.org/x/sys
- add to keeplibs:
 third_party/libtess2
 third_party/devtools-frontend/src/node_modules/fast-glob");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~132.0.6834.83~bp156.2.69.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~132.0.6834.83~bp156.2.69.1", rls:"openSUSELeap15.6"))) {
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
