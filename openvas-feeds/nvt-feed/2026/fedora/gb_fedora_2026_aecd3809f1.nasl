# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.971019910038091021");
  script_cve_id("CVE-2026-2239");
  script_tag(name:"creation_date", value:"2026-03-09 04:44:32 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-26 21:17:04 +0000 (Thu, 26 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-aecd3809f1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-aecd3809f1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-aecd3809f1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437676");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp' package(s) announced via the FEDORA-2026-aecd3809f1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security update fixing the loader for PSD files.");

  script_tag(name:"affected", value:"'gimp' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"gimp", rpm:"gimp~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debuginfo", rpm:"gimp-debuginfo~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-debugsource", rpm:"gimp-debugsource~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-tools", rpm:"gimp-devel-tools~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-devel-tools-debuginfo", rpm:"gimp-devel-tools-debuginfo~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~3.0.8~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gimp-libs-debuginfo", rpm:"gimp-libs-debuginfo~3.0.8~5.fc42", rls:"FC42"))) {
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
