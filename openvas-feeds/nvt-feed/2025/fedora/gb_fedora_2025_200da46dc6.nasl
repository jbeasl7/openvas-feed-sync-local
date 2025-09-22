# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.2001009746100996");
  script_cve_id("CVE-2025-7545", "CVE-2025-7546");
  script_tag(name:"creation_date", value:"2025-07-28 04:20:29 +0000 (Mon, 28 Jul 2025)");
  script_version("2025-07-31T05:44:45+0000");
  script_tag(name:"last_modification", value:"2025-07-31 05:44:45 +0000 (Thu, 31 Jul 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-30 15:59:59 +0000 (Wed, 30 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-200da46dc6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-200da46dc6");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-200da46dc6");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379831");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379838");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379839");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2379845");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-binutils' package(s) announced via the FEDORA-2025-200da46dc6 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for CVE-2025-7545 and CVE-2025-7546.");

  script_tag(name:"affected", value:"'mingw-binutils' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils", rpm:"mingw-binutils~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-debuginfo", rpm:"mingw-binutils-debuginfo~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-debugsource", rpm:"mingw-binutils-debugsource~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-generic", rpm:"mingw-binutils-generic~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw-binutils-generic-debuginfo", rpm:"mingw-binutils-generic-debuginfo~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-binutils", rpm:"mingw32-binutils~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-binutils-debuginfo", rpm:"mingw32-binutils-debuginfo~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-binutils", rpm:"mingw64-binutils~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-binutils-debuginfo", rpm:"mingw64-binutils-debuginfo~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucrt64-binutils", rpm:"ucrt64-binutils~2.42~3.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucrt64-binutils-debuginfo", rpm:"ucrt64-binutils-debuginfo~2.42~3.fc41", rls:"FC41"))) {
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
