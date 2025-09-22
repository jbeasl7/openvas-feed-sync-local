# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.697973985248102");
  script_cve_id("CVE-2023-44270", "CVE-2024-21535");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 20:36:29 +0000 (Thu, 17 Oct 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-6aa3b5248f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-6aa3b5248f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-6aa3b5248f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318704");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322770");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2328666");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2330305");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jupyterlab, python-notebook' package(s) announced via the FEDORA-2024-6aa3b5248f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New jupyterlab and notebook fixing some CVEs.");

  script_tag(name:"affected", value:"'jupyterlab, python-notebook' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"jupyterlab", rpm:"jupyterlab~4.3.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-notebook", rpm:"python-notebook~7.3.1~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-notebook", rpm:"python3-notebook~7.3.1~1.fc42", rls:"FC42"))) {
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
