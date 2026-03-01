# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.449710201022383");
  script_cve_id("CVE-2026-0716", "CVE-2026-0719");
  script_tag(name:"creation_date", value:"2026-02-18 04:41:15 +0000 (Wed, 18 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-13 06:15:49 +0000 (Tue, 13 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-44af0f2383)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-44af0f2383");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-44af0f2383");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2427902");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2427905");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2427909");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2427912");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-libsoup' package(s) announced via the FEDORA-2026-44af0f2383 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for CVE-2026-0716, CVE-2026-0719.");

  script_tag(name:"affected", value:"'mingw-libsoup' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-libsoup", rpm:"mingw-libsoup~2.74.3~17.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup", rpm:"mingw32-libsoup~2.74.3~17.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup-debuginfo", rpm:"mingw32-libsoup-debuginfo~2.74.3~17.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup", rpm:"mingw64-libsoup~2.74.3~17.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup-debuginfo", rpm:"mingw64-libsoup-debuginfo~2.74.3~17.fc43", rls:"FC43"))) {
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
