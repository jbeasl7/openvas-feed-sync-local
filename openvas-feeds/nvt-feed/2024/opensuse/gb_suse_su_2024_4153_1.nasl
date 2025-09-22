# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856779");
  script_cve_id("CVE-2024-11168");
  script_tag(name:"creation_date", value:"2024-12-04 05:00:24 +0000 (Wed, 04 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4153-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244153-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233307");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019897.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python310' package(s) announced via the SUSE-SU-2024:4153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python310 fixes the following issues:

- CVE-2024-11168: improper validation of IPv6 and IPvFuture addresses. (bsc#1233307)

Bug fixes:

- Remove -IVendor/ from python-config. (bsc#1231795)
- Include renaming :noindex: option to :no-index: in Sphinx 7.2. (bsc#1232750)");

  script_tag(name:"affected", value:"'python310' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit", rpm:"libpython3_10-1_0-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit", rpm:"python310-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit", rpm:"python310-base-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc", rpm:"python310-doc~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc-devhelp", rpm:"python310-doc-devhelp~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite", rpm:"python310-testsuite~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.15~150400.4.63.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0", rpm:"libpython3_10-1_0~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_10-1_0-32bit", rpm:"libpython3_10-1_0-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310", rpm:"python310~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-32bit", rpm:"python310-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base", rpm:"python310-base~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-base-32bit", rpm:"python310-base-32bit~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-curses", rpm:"python310-curses~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-dbm", rpm:"python310-dbm~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-devel", rpm:"python310-devel~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc", rpm:"python310-doc~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-doc-devhelp", rpm:"python310-doc-devhelp~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-idle", rpm:"python310-idle~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-testsuite", rpm:"python310-testsuite~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tk", rpm:"python310-tk~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python310-tools", rpm:"python310-tools~3.10.15~150400.4.63.1", rls:"openSUSELeap15.6"))) {
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
