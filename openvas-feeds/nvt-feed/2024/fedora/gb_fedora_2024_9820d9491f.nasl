# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887302");
  script_cve_id("CVE-2024-4067", "CVE-2024-4068", "CVE-2024-4216");
  script_tag(name:"creation_date", value:"2024-08-06 07:33:14 +0000 (Tue, 06 Aug 2024)");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-19 13:27:28 +0000 (Fri, 19 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-9820d9491f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-9820d9491f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-9820d9491f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278855");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280626");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280781");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pgadmin4' package(s) announced via the FEDORA-2024-9820d9491f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport security fixes for CVE-2024-4216, CVE-2024-4068, CVE-2024-4067.");

  script_tag(name:"affected", value:"'pgadmin4' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4", rpm:"pgadmin4~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-debugsource", rpm:"pgadmin4-debugsource~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-httpd", rpm:"pgadmin4-httpd~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-cs", rpm:"pgadmin4-langpack-cs~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-de", rpm:"pgadmin4-langpack-de~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-es", rpm:"pgadmin4-langpack-es~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-fr", rpm:"pgadmin4-langpack-fr~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-it", rpm:"pgadmin4-langpack-it~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ja", rpm:"pgadmin4-langpack-ja~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ko", rpm:"pgadmin4-langpack-ko~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-pl", rpm:"pgadmin4-langpack-pl~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-ru", rpm:"pgadmin4-langpack-ru~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-langpack-zh", rpm:"pgadmin4-langpack-zh~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt", rpm:"pgadmin4-qt~7.8~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pgadmin4-qt-debuginfo", rpm:"pgadmin4-qt-debuginfo~7.8~7.fc39", rls:"FC39"))) {
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
