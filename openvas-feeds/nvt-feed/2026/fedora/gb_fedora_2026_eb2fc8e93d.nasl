# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.10198210299810193100");
  script_cve_id("CVE-2026-25727", "CVE-2026-3336", "CVE-2026-3337", "CVE-2026-3338");
  script_tag(name:"creation_date", value:"2026-03-13 04:36:55 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-13T15:49:08+0000");
  script_tag(name:"last_modification", value:"2026-03-13 15:49:08 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-24 15:23:35 +0000 (Tue, 24 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-eb2fc8e93d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-eb2fc8e93d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-eb2fc8e93d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438090");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2438156");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444169");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444179");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2444189");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'task' package(s) announced via the FEDORA-2026-eb2fc8e93d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to new release, includes updated dependencies that fix for a number of CVEs");

  script_tag(name:"affected", value:"'task' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"task", rpm:"task~3.4.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-debuginfo", rpm:"task-debuginfo~3.4.2~3.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-debugsource", rpm:"task-debugsource~3.4.2~3.fc43", rls:"FC43"))) {
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
