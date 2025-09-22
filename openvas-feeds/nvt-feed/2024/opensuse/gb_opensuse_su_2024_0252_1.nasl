# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856344");
  script_cve_id("CVE-2024-6772", "CVE-2024-6773", "CVE-2024-6774", "CVE-2024-6775", "CVE-2024-6776", "CVE-2024-6777", "CVE-2024-6778", "CVE-2024-6779");
  script_tag(name:"creation_date", value:"2024-08-19 04:00:23 +0000 (Mon, 19 Aug 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-26 15:41:39 +0000 (Thu, 26 Dec 2024)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0252-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0252-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2EALRZ2J2EDX32BAG7AQ44YU767S375L/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera' package(s) announced via the openSUSE-SU-2024:0252-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

- Update to 112.0.5197.53
 * CHR-9814 Update Chromium on desktop-stable-126-5197 to
 126.0.6478.226
 * DNA-116974 Site settings popup size not expanding causing
 display issues
 * DNA-117115 Tab islands are extending partially after Workspace
 change
 * DNA-117708 H.264 SW decoding only possible if HW decoding
 is possible
 * DNA-117792 Crash at content::RenderWidgetHostImpl::
 ForwardMouseEventWithLatencyInfo(blink::
 WebMouseEvent const&, ui::LatencyInfo const&)
- The update to chromium >= 126.0.6478.182 fixes following issues:
 CVE-2024-6772, CVE-2024-6773, CVE-2024-6774, CVE-2024-6775,
 CVE-2024-6776, CVE-2024-6777, CVE-2024-6778, CVE-2024-6779

- Update to 112.0.5197.30
 * CHR-9416 Updating Chromium on desktop-stable-* branches");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~112.0.5197.53~lp155.3.57.1", rls:"openSUSELeap15.5"))) {
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
