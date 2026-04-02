# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.296581002102498");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2025-6075", "CVE-2026-0672");
  script_tag(name:"creation_date", value:"2026-03-16 04:56:17 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-16T06:13:25+0000");
  script_tag(name:"last_modification", value:"2026-03-16 06:13:25 +0000 (Mon, 16 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-04 18:46:13 +0000 (Wed, 04 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-29658d2f4b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-29658d2f4b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-29658d2f4b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2413055");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431815");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431824");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431843");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.11' package(s) announced via the FEDORA-2026-29658d2f4b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 3.11.15");

  script_tag(name:"affected", value:"'python3.11' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.11", rpm:"python3.11~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debug", rpm:"python3.11-debug~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debuginfo", rpm:"python3.11-debuginfo~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-debugsource", rpm:"python3.11-debugsource~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-devel", rpm:"python3.11-devel~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-idle", rpm:"python3.11-idle~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-libs", rpm:"python3.11-libs~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-test", rpm:"python3.11-test~3.11.15~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.11-tkinter", rpm:"python3.11-tkinter~3.11.15~1.fc43", rls:"FC43"))) {
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
