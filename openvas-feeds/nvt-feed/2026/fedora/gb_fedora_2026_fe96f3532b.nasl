# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10210196102353298");
  script_cve_id("CVE-2025-11839", "CVE-2025-11840", "CVE-2025-69644", "CVE-2025-69645", "CVE-2025-69646", "CVE-2025-69647", "CVE-2025-69648", "CVE-2025-69649", "CVE-2025-69650", "CVE-2025-69651", "CVE-2025-69652", "CVE-2026-4647");
  script_tag(name:"creation_date", value:"2026-04-06 04:59:34 +0000 (Mon, 06 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-11 15:51:05 +0000 (Wed, 11 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-fe96f3532b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-fe96f3532b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-fe96f3532b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404507");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2404556");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445279");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445283");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445286");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2445389");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448118");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448126");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448137");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448145");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2448153");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2450319");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-binutils' package(s) announced via the FEDORA-2026-fe96f3532b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for multiple CVEs.");

  script_tag(name:"affected", value:"'mingw-binutils' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils", rpm:"mingw-binutils~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-debuginfo", rpm:"mingw-binutils-debuginfo~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-debugsource", rpm:"mingw-binutils-debugsource~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-generic", rpm:"mingw-binutils-generic~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-generic-debuginfo", rpm:"mingw-binutils-generic-debuginfo~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-binutils", rpm:"mingw32-binutils~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-binutils-debuginfo", rpm:"mingw32-binutils-debuginfo~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-binutils", rpm:"mingw64-binutils~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-binutils-debuginfo", rpm:"mingw64-binutils-debuginfo~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucrt64-binutils", rpm:"ucrt64-binutils~2.43.1~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucrt64-binutils-debuginfo", rpm:"ucrt64-binutils-debuginfo~2.43.1~6.fc42", rls:"FC42"))) {
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
