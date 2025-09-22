# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833485");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-43785", "CVE-2023-43786", "CVE-2023-43787");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 13:18:05 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:48:44 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libX11 (SUSE-SU-2023:3963-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3963-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TM3QMGWNQ77CS7XCACRLJ2OLSSVI7MQY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libX11'
  package(s) announced via the SUSE-SU-2023:3963-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libX11 fixes the following issues:

  * CVE-2023-43786: Fixed stack exhaustion from infinite recursion in
      PutSubImage() (bsc#1215684).

  * CVE-2023-43787: Fixed integer overflow in XCreateImage() leading to a heap
      overflow (bsc#1215685).

  * CVE-2023-43785: Fixed out-of-bounds memory access in _XkbReadKeySyms()
      (bsc#1215683).

  ##");

  script_tag(name:"affected", value:"'libX11' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel-32bit", rpm:"libX11-devel-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.33.1##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel-32bit", rpm:"libX11-devel-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.33.1##", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel-32bit", rpm:"libX11-devel-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel-32bit", rpm:"libX11-devel-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.33.1", rls:"openSUSELeap15.5"))) {
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
