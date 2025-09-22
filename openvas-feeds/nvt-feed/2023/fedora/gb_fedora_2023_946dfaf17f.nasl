# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884822");
  script_cve_id("CVE-2022-41717");
  script_tag(name:"creation_date", value:"2023-09-16 01:16:10 +0000 (Sat, 16 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 17:50:12 +0000 (Mon, 12 Dec 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-946dfaf17f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-946dfaf17f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-946dfaf17f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161274");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2163274");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2229918");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'htmltest' package(s) announced via the FEDORA-2023-946dfaf17f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2022-41717");

  script_tag(name:"affected", value:"'htmltest' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-wjdp-htmltest-devel", rpm:"golang-github-wjdp-htmltest-devel~0.17.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmltest", rpm:"htmltest~0.17.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmltest-debuginfo", rpm:"htmltest-debuginfo~0.17.0~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"htmltest-debugsource", rpm:"htmltest-debugsource~0.17.0~4.fc39", rls:"FC39"))) {
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
