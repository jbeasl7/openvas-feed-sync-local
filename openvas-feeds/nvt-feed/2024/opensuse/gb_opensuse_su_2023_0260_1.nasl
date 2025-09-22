# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833423");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2021-21236", "CVE-2023-27586");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 18:23:58 +0000 (Thu, 23 Mar 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:17:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for python (openSUSE-SU-2023:0260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0260-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2GIY4HBHI7WUBHUAMEZKWBMEPOUYNCTU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the openSUSE-SU-2023:0260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-CairoSVG fixes the following issues:

  - CVE-2023-27586: Don't allow fetching external files unless explicitly
       asked for. (boo#1209538)

  - Update to version 2.5.2

  * Fix marker path scale

  - Update to version 2.5.1 (boo#1180648, CVE-2021-21236):

  * Security fix: When processing SVG files, CairoSVG was using two
         regular expressions which are vulnerable to Regular Expression Denial
         of Service (REDoS). If an attacker provided a malicious SVG, it could
         make CairoSVG get stuck processing the file for a very long time.

  * Fix marker positions for unclosed paths

  * Follow hint when only output_width or output_height is set

  * Handle opacity on raster images

  * Dont crash when use tags reference unknown tags

  * Take care of the next letter when A/a is replaced by l

  * Fix misalignment in node.vertices

  - Updates for version 2.5.0.

  * Drop support of Python 3.5, add support of Python 3.9.

  * Add EPS export

  * Add background-color, negate-colors, and invert-images options

  * Improve support for font weights

  * Fix opacity of patterns and gradients

  * Support auto-start-reverse value for orient

  * Draw images contained in defs

  * Add Exif transposition support

  * Handle dominant-baseline

  * Support transform-origin");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python3-CairoSVG", rpm:"python3-CairoSVG~2.5.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-CairoSVG", rpm:"python3-CairoSVG~2.5.2~bp155.3.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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