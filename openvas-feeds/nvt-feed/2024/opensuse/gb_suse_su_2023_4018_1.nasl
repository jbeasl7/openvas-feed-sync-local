# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833218");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-39323");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 18:04:15 +0000 (Thu, 04 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:47 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.20 (SUSE-SU-2023:4018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4018-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6Y5CH5R22RMXP5LSKHOAOUDGQCXM3EYZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.20'
  package(s) announced via the SUSE-SU-2023:4018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.20 fixes the following issues:

  * Updated to version 1.20.9 (bsc#1206346):

  * CVE-2023-39323: Fixed an arbitrary execution issue during build time due to
      path directive bypass (bsc#1215985).

  ##");

  script_tag(name:"affected", value:"'go1.20' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.20-doc", rpm:"go1.20-doc~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-race", rpm:"go1.20-race~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20", rpm:"go1.20~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-debuginfo", rpm:"go1.20-debuginfo~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-doc", rpm:"go1.20-doc~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-race", rpm:"go1.20-race~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20", rpm:"go1.20~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-debuginfo", rpm:"go1.20-debuginfo~1.20.9~150000.1.26.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.20-doc", rpm:"go1.20-doc~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-race", rpm:"go1.20-race~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20", rpm:"go1.20~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-debuginfo", rpm:"go1.20-debuginfo~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-doc", rpm:"go1.20-doc~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-race", rpm:"go1.20-race~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20", rpm:"go1.20~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.20-debuginfo", rpm:"go1.20-debuginfo~1.20.9~150000.1.26.1", rls:"openSUSELeap15.5"))) {
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