# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.3101985235527");
  script_cve_id("CVE-2025-31498");
  script_tag(name:"creation_date", value:"2025-05-12 04:06:45 +0000 (Mon, 12 May 2025)");
  script_version("2025-05-12T05:40:33+0000");
  script_tag(name:"last_modification", value:"2025-05-12 05:40:33 +0000 (Mon, 12 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-3eb5235527)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-3eb5235527");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-3eb5235527");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358568");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358571");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2361835");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the FEDORA-2025-3eb5235527 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 22.15.0");

  script_tag(name:"affected", value:"'nodejs22' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-debuginfo", rpm:"nodejs22-debuginfo~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-debugsource", rpm:"nodejs22-debugsource~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-devel", rpm:"nodejs22-devel~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-docs", rpm:"nodejs22-docs~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-full-i18n", rpm:"nodejs22-full-i18n~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-libs", rpm:"nodejs22-libs~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-libs-debuginfo", rpm:"nodejs22-libs-debuginfo~22.15.0~2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-npm", rpm:"nodejs22-npm~10.9.2~1.22.15.0.2.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"v8-12.4-devel", rpm:"v8-12.4-devel~12.4.254.21~1.22.15.0.2.fc40", rls:"FC40"))) {
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
