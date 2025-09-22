# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0145.1");
  script_cve_id("CVE-2025-4050", "CVE-2025-4051", "CVE-2025-4052", "CVE-2025-4096");
  script_tag(name:"creation_date", value:"2025-05-07 10:32:02 +0000 (Wed, 07 May 2025)");
  script_version("2025-05-08T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-05-08 05:40:19 +0000 (Thu, 08 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0145-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0145-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IHE6M4AT6OVVDTRDDU6SOI4R4QJUUUFP/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242153");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the openSUSE-SU-2025:0145-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

- Chromium 136.0.7103.48
 (stable release 2025-04-29) (boo#1242153)
 * CVE-2025-4096: Heap buffer overflow in HTML. Reported by Anonymous on 2025-04-11
 * CVE-2025-4050: Out of bounds memory access in DevTools. Reported by Anonymous on 2025-04-09
 * CVE-2025-4051: Insufficient data validation in DevTools. Reported by Daniel Frojdendahl on 2025-03-1
 * CVE-2025-4052: Inappropriate implementation in DevTools. Reported by vanillawebdev on 2025-03-10
- bump esbuild from 0.24.0 to 0.25.1
 * Fix incorrect paths in inline source maps (#4070, #4075, #4105)
 * Fix invalid generated source maps (#4080, #4082, #4104, #4107)
 * Fix a regression with non-file source map paths (#4078)
 * Update Go from 1.23.5 to 1.23.7 (#4076, #4077)

- Chromium 135.0.7049.114
 (stable release 2025-04-22)
 * stability fixes");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~136.0.7103.59~bp156.2.113.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~136.0.7103.59~bp156.2.113.2", rls:"openSUSELeap15.6"))) {
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
