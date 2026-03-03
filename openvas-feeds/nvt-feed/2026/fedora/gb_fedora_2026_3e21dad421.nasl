# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.31012110097100421");
  script_cve_id("CVE-2026-2239");
  script_tag(name:"creation_date", value:"2026-03-02 04:38:01 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-3e21dad421)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-3e21dad421");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-3e21dad421");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437677");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the FEDORA-2026-3e21dad421 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security update fixing the loader for PSD files.");

  script_tag(name:"affected", value:"'gimp' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-tools", rpm:"gimp-devel-tools~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-tools-debuginfo", rpm:"gimp-devel-tools-debuginfo~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~3.0.8~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs-debuginfo", rpm:"gimp-libs-debuginfo~3.0.8~5.fc43", rls:"FC43"))) {
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
