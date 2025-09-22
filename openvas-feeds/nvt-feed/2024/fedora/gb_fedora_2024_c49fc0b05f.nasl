# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886346");
  script_cve_id("CVE-2024-2243");
  script_tag(name:"creation_date", value:"2024-03-29 02:11:31 +0000 (Fri, 29 Mar 2024)");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-08 18:54:54 +0000 (Fri, 08 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-c49fc0b05f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c49fc0b05f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-c49fc0b05f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270495");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270496");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'csmock' package(s) announced via the FEDORA-2024-c49fc0b05f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- update to latest upstream (fixes CVE-2024-2243)");

  script_tag(name:"affected", value:"'csmock' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"csbuild", rpm:"csbuild~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock", rpm:"csmock~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-common", rpm:"csmock-common~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-bandit", rpm:"csmock-plugin-bandit~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-cbmc", rpm:"csmock-plugin-cbmc~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-clang", rpm:"csmock-plugin-clang~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-cppcheck", rpm:"csmock-plugin-cppcheck~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-divine", rpm:"csmock-plugin-divine~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-gitleaks", rpm:"csmock-plugin-gitleaks~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-infer", rpm:"csmock-plugin-infer~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-pylint", rpm:"csmock-plugin-pylint~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-shellcheck", rpm:"csmock-plugin-shellcheck~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-smatch", rpm:"csmock-plugin-smatch~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-snyk", rpm:"csmock-plugin-snyk~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-strace", rpm:"csmock-plugin-strace~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-symbiotic", rpm:"csmock-plugin-symbiotic~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-unicontrol", rpm:"csmock-plugin-unicontrol~3.5.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"csmock-plugin-valgrind", rpm:"csmock-plugin-valgrind~3.5.3~1.fc40", rls:"FC40"))) {
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
