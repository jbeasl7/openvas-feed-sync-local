# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.454786081012");
  script_cve_id("CVE-2024-10963");
  script_tag(name:"creation_date", value:"2024-12-06 04:09:03 +0000 (Fri, 06 Dec 2024)");
  script_version("2024-12-06T15:41:14+0000");
  script_tag(name:"last_modification", value:"2024-12-06 15:41:14 +0000 (Fri, 06 Dec 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-08 07:15:06 +0000 (Fri, 08 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-45478608e2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-45478608e2");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-45478608e2");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2324299");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the FEDORA-2024-45478608e2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pam_access: rework resolving of tokens as hostname.");

  script_tag(name:"affected", value:"'pam' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"pam", rpm:"pam~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debuginfo", rpm:"pam-debuginfo~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-debugsource", rpm:"pam-debugsource~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-devel", rpm:"pam-devel~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-doc", rpm:"pam-doc~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-libs", rpm:"pam-libs~1.6.1~5.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam-libs-debuginfo", rpm:"pam-libs-debuginfo~1.6.1~5.fc40", rls:"FC40"))) {
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
