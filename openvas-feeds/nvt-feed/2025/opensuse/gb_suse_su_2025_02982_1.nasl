# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02982.1");
  script_cve_id("CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-08-27 04:06:44 +0000 (Wed, 27 Aug 2025)");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02982-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02982-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502982-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247249");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041354.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python312' package(s) announced via the SUSE-SU-2025:02982-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python312 fixes the following issues:

- CVE-2025-8194: Fixed denial of service caused by tar archives with negative offsets (bsc#1247249).");

  script_tag(name:"affected", value:"'python312' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_12-1_0", rpm:"libpython3_12-1_0~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_12-1_0-32bit", rpm:"libpython3_12-1_0-32bit~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312", rpm:"python312~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-32bit", rpm:"python312-32bit~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base", rpm:"python312-base~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base-32bit", rpm:"python312-base-32bit~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-curses", rpm:"python312-curses~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-dbm", rpm:"python312-dbm~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-devel", rpm:"python312-devel~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-doc", rpm:"python312-doc~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-doc-devhelp", rpm:"python312-doc-devhelp~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-idle", rpm:"python312-idle~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-testsuite", rpm:"python312-testsuite~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tk", rpm:"python312-tk~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tools", rpm:"python312-tools~3.12.11~150600.3.36.1", rls:"openSUSELeap15.6"))) {
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
