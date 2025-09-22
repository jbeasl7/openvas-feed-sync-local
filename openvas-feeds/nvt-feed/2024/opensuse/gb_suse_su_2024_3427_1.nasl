# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856508");
  script_cve_id("CVE-2024-6232", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2024-09-26 04:01:44 +0000 (Thu, 26 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-20 16:02:16 +0000 (Tue, 20 Aug 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3427-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3427-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243427-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230227");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019516.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311' package(s) announced via the SUSE-SU-2024:3427-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

Update python311 to version 3.11.10.

- CVE-2024-6232: excessive backtracking when parsing tarfile headers leads to ReDoS. (bsc#1230227)
- CVE-2024-7592: quadratic algorithm used when parsing cookies leads to excessive resource consumption. (bsc#1229596)
- CVE-2024-8088: lack of name validation when extracting a zip archive leads to infinite loops. (bsc#1229704)");

  script_tag(name:"affected", value:"'python311' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0-32bit", rpm:"libpython3_11-1_0-32bit~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-32bit", rpm:"python311-32bit~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base-32bit", rpm:"python311-base-32bit~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-testsuite", rpm:"python311-testsuite~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.10~150600.3.6.1", rls:"openSUSELeap15.6"))) {
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
