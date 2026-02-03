# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1026019821026097");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59464", "CVE-2025-59465", "CVE-2025-59466", "CVE-2025-62408", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 14:56:59 +0000 (Wed, 21 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-f601b2f60a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f601b2f60a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f601b2f60a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2430298");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431454");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431461");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431468");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431475");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431490");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431491");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431492");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs20' package(s) announced via the FEDORA-2026-f601b2f60a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 20.20.0

----

Update to version 20.19.6");

  script_tag(name:"affected", value:"'nodejs20' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs20", rpm:"nodejs20~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debuginfo", rpm:"nodejs20-debuginfo~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-debugsource", rpm:"nodejs20-debugsource~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-devel", rpm:"nodejs20-devel~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-docs", rpm:"nodejs20-docs~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-full-i18n", rpm:"nodejs20-full-i18n~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-libs", rpm:"nodejs20-libs~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-libs-debuginfo", rpm:"nodejs20-libs-debuginfo~20.20.0~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs20-npm", rpm:"nodejs20-npm~10.8.2~1.20.20.0.2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-11.3-devel", rpm:"v8-11.3-devel~11.3.244.8~1.20.20.0.2.fc43", rls:"FC43"))) {
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
