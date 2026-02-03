# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.59910040910110010297");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59464", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 14:56:59 +0000 (Wed, 21 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-5cd409edfa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-5cd409edfa");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-5cd409edfa");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421027");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2430300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431456");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431463");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431470");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431477");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431496");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431497");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431498");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs24' package(s) announced via the FEDORA-2026-5cd409edfa advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 24.13.0");

  script_tag(name:"affected", value:"'nodejs24' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs24", rpm:"nodejs24~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-debuginfo", rpm:"nodejs24-debuginfo~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-debugsource", rpm:"nodejs24-debugsource~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-devel", rpm:"nodejs24-devel~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-docs", rpm:"nodejs24-docs~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-full-i18n", rpm:"nodejs24-full-i18n~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-libs", rpm:"nodejs24-libs~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-libs-debuginfo", rpm:"nodejs24-libs-debuginfo~24.13.0~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs24-npm", rpm:"nodejs24-npm~11.6.2~1.24.13.0.4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-13.6-devel", rpm:"v8-13.6-devel~13.6.233.17~1.24.13.0.4.fc43", rls:"FC43"))) {
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
