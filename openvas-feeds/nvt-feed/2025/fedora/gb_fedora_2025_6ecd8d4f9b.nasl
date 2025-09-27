# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.61019910081004102998");
  script_cve_id("CVE-2025-58367");
  script_tag(name:"creation_date", value:"2025-09-26 04:05:15 +0000 (Fri, 26 Sep 2025)");
  script_version("2025-09-26T05:38:41+0000");
  script_tag(name:"last_modification", value:"2025-09-26 05:38:41 +0000 (Fri, 26 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-6ecd8d4f9b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6ecd8d4f9b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6ecd8d4f9b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2393899");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-deepdiff, python-orderly-set' package(s) announced via the FEDORA-2025-6ecd8d4f9b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 8.6.1");

  script_tag(name:"affected", value:"'python-deepdiff, python-orderly-set' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-deepdiff", rpm:"python-deepdiff~8.6.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-orderly-set", rpm:"python-orderly-set~5.5.0~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-deepdiff+cli", rpm:"python3-deepdiff+cli~8.6.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-deepdiff", rpm:"python3-deepdiff~8.6.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-orderly-set", rpm:"python3-orderly-set~5.5.0~2.fc42", rls:"FC42"))) {
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
