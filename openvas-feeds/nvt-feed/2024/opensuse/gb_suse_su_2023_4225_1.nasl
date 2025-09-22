# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833126");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-46228");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-25 14:51:06 +0000 (Wed, 25 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:39:35 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for zchunk (SUSE-SU-2023:4225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4225-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/J5V3SFF7NTIR5RHL5V3PKL4HHUHVOYMM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zchunk'
  package(s) announced via the SUSE-SU-2023:4225-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zchunk fixes the following issues:

  * CVE-2023-46228: Fixed a handle overflow errors in malformed zchunk files.
      (bsc#1216268)

  ##");

  script_tag(name:"affected", value:"'zchunk' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck-devel", rpm:"libzck-devel~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck-devel", rpm:"libzck-devel~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck-devel", rpm:"libzck-devel~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck-devel", rpm:"libzck-devel~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk", rpm:"zchunk~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck-devel", rpm:"libzck-devel~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debuginfo", rpm:"zchunk-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1", rpm:"libzck1~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzck1-debuginfo", rpm:"libzck1-debuginfo~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zchunk-debugsource", rpm:"zchunk-debugsource~1.1.16~150400.3.7.1", rls:"openSUSELeapMicro5.4"))) {
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