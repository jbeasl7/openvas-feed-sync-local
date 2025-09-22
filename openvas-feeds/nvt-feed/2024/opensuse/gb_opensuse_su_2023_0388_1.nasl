# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833563");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-43907");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-03 20:57:20 +0000 (Tue, 03 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:49:39 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for optipng (openSUSE-SU-2023:0388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0388-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M4KHRFT5CJKRYROUB7T7FZQUZAVRJESF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'optipng'
  package(s) announced via the openSUSE-SU-2023:0388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for optipng fixes the following issues:

     Update to 0.7.8:

  * CVE-2023-43907: Fixed a global-buffer-overflow vulnerability in the GIF
       reader (boo#1215937).

  * Fixed a stack-print-after-scope defect in the error handler.

  * Fixed an assertion failure in the image reduction module.

  * Fixed the command-line wildargs expansion in the Windows port.

  * Refactored the structured exception handling.");

  script_tag(name:"affected", value:"'optipng' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debuginfo", rpm:"optipng-debuginfo~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debugsource", rpm:"optipng-debugsource~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debuginfo", rpm:"optipng-debuginfo~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"optipng-debugsource", rpm:"optipng-debugsource~0.7.8~bp154.3.5.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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