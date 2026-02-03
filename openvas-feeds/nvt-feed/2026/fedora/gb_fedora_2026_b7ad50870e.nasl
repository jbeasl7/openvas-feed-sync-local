# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9879710050870101");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59464", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 14:56:59 +0000 (Wed, 21 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-b7ad50870e)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-b7ad50870e");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-b7ad50870e");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2430295");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431452");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431459");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431466");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431473");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431484");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431485");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431486");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the FEDORA-2026-b7ad50870e advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 22.22.0");

  script_tag(name:"affected", value:"'nodejs22' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-debuginfo", rpm:"nodejs-debuginfo~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-devel", rpm:"nodejs-devel~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-docs", rpm:"nodejs-docs~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-full-i18n", rpm:"nodejs-full-i18n~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs", rpm:"nodejs-libs~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-libs-debuginfo", rpm:"nodejs-libs-debuginfo~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-npm", rpm:"nodejs-npm~10.9.4~1.22.22.0.2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-debuginfo", rpm:"nodejs22-debuginfo~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-debugsource", rpm:"nodejs22-debugsource~22.22.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-12.4-devel", rpm:"v8-12.4-devel~12.4.254.21~1.22.22.0.2.fc42", rls:"FC42"))) {
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
