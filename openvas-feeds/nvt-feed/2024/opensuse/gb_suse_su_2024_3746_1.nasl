# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856617");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-7254");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-10-23 04:00:29 +0000 (Wed, 23 Oct 2024)");
  script_name("openSUSE: Security Advisory for protobuf (SUSE-SU-2024:3746-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3746-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3EICRVQ7CQU5DD673TA33LZMPLAJR72X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'protobuf'
  package(s) announced via the SUSE-SU-2024:3746-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for protobuf fixes the following issues:

  * CVE-2024-7254: Fixed stack overflow vulnerability in Protocol Buffer
      (bsc#1230778)");

  script_tag(name:"affected", value:"'protobuf' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"protobuf-java", rpm:"protobuf-java~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0", rpm:"libprotobuf25_1_0~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-debuginfo", rpm:"libprotoc25_1_0-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-debuginfo", rpm:"libprotobuf25_1_0-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-protobuf", rpm:"python311-protobuf~4.25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0", rpm:"libprotoc25_1_0~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-debuginfo", rpm:"libprotobuf-lite25_1_0-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit", rpm:"libprotobuf-lite25_1_0-32bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit", rpm:"libprotoc25_1_0-32bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-32bit-debuginfo", rpm:"libprotoc25_1_0-32bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit", rpm:"libprotobuf25_1_0-32bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-32bit-debuginfo", rpm:"libprotobuf25_1_0-32bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-32bit-debuginfo", rpm:"libprotobuf-lite25_1_0-32bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-64bit-debuginfo", rpm:"libprotobuf25_1_0-64bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-64bit", rpm:"libprotoc25_1_0-64bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-64bit-debuginfo", rpm:"libprotobuf-lite25_1_0-64bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0-64bit-debuginfo", rpm:"libprotoc25_1_0-64bit-debuginfo~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0-64bit", rpm:"libprotobuf-lite25_1_0-64bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0-64bit", rpm:"libprotobuf25_1_0-64bit~25.1~150400.9.10.1", rls:"openSUSELeap15.4"))) {
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
