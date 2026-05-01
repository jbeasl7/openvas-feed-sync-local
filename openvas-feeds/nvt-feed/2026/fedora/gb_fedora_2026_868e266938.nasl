# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.868101266938");
  script_cve_id("CVE-2024-25621", "CVE-2025-47913", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61725", "CVE-2025-66564", "CVE-2025-69725", "CVE-2026-22703");
  script_tag(name:"creation_date", value:"2026-04-13 05:05:57 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-31 02:29:30 +0000 (Wed, 31 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2026-868e266938)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-868e266938");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-868e266938");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408364");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2408748");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2409835");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2410785");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2411681");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2412610");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2419050");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2420630");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421872");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2429310");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2441182");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trivy' package(s) announced via the FEDORA-2026-868e266938 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 0.69.3");

  script_tag(name:"affected", value:"'trivy' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"trivy", rpm:"trivy~0.69.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trivy-debuginfo", rpm:"trivy-debuginfo~0.69.3~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"trivy-debugsource", rpm:"trivy-debugsource~0.69.3~1.fc43", rls:"FC43"))) {
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
