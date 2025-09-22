# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886289");
  script_cve_id("CVE-2022-38223", "CVE-2023-38252", "CVE-2023-38253", "CVE-2023-4255");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:03 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 19:20:24 +0000 (Tue, 16 Aug 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2024-aeb75f8b5b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-aeb75f8b5b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-aeb75f8b5b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222775");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222776");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222779");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222780");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255207");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255208");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m' package(s) announced via the FEDORA-2024-aeb75f8b5b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Added upstream patch to fix out-of-bounds access due to multiple backspaces to address incomplete fix for CVE-2022-38223 (#2222775, #2222780, #2255207)");

  script_tag(name:"affected", value:"'w3m' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3~63.git20230121.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-debuginfo", rpm:"w3m-debuginfo~0.5.3~63.git20230121.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-debugsource", rpm:"w3m-debugsource~0.5.3~63.git20230121.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-img", rpm:"w3m-img~0.5.3~63.git20230121.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-img-debuginfo", rpm:"w3m-img-debuginfo~0.5.3~63.git20230121.fc40", rls:"FC40"))) {
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
