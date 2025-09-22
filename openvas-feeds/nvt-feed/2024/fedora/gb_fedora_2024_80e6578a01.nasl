# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885567");
  script_cve_id("CVE-2021-42260", "CVE-2023-34194", "CVE-2023-40462");
  script_tag(name:"creation_date", value:"2024-01-18 09:15:29 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-04 23:15:25 +0000 (Mon, 04 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-80e6578a01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-80e6578a01");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-80e6578a01");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253716");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2253718");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254376");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254381");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tinyxml' package(s) announced via the FEDORA-2024-80e6578a01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bugfix release. Includes security fixes for CVE-2021-42260 and CVE-2023-34194 and a fix for incorrect text element encoding (upstream isssue #51).");

  script_tag(name:"affected", value:"'tinyxml' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"tinyxml", rpm:"tinyxml~2.6.2~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml-debuginfo", rpm:"tinyxml-debuginfo~2.6.2~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml-debugsource", rpm:"tinyxml-debugsource~2.6.2~28.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tinyxml-devel", rpm:"tinyxml-devel~2.6.2~28.fc39", rls:"FC39"))) {
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
