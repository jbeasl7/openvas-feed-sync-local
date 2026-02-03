# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0314.1");
  script_cve_id("CVE-2025-12084", "CVE-2025-13836", "CVE-2025-13837");
  script_tag(name:"creation_date", value:"2026-02-02 04:42:36 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-30 15:08:14 +0000 (Tue, 30 Dec 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0314-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260314-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254997");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023980.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python311' package(s) announced via the SUSE-SU-2026:0314-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python311 fixes the following issues:

- CVE-2025-12084: prevent quadratic behavior in node ID cache clearing (bsc#1254997).
- CVE-2025-13836: prevent reading an HTTP response from a server, if no read amount is specified, with using Content-Length per default as the length (bsc#1254400).
- CVE-2025-13837: protect against OOM when loading malicious content (bsc#1254401).");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0", rpm:"libpython3_11-1_0~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_11-1_0-32bit", rpm:"libpython3_11-1_0-32bit~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311", rpm:"python311~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-32bit", rpm:"python311-32bit~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base", rpm:"python311-base~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-base-32bit", rpm:"python311-base-32bit~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-curses", rpm:"python311-curses~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-dbm", rpm:"python311-dbm~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-devel", rpm:"python311-devel~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc", rpm:"python311-doc~3.11.14~150600.3.41.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-doc-devhelp", rpm:"python311-doc-devhelp~3.11.14~150600.3.41.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-idle", rpm:"python311-idle~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-testsuite", rpm:"python311-testsuite~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tk", rpm:"python311-tk~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-tools", rpm:"python311-tools~3.11.14~150600.3.41.2", rls:"openSUSELeap15.6"))) {
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
