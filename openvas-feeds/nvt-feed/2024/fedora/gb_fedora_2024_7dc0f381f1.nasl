# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.71009901023811021");
  script_cve_id("CVE-2024-6232");
  script_tag(name:"creation_date", value:"2024-09-19 06:52:24 +0000 (Thu, 19 Sep 2024)");
  script_version("2024-09-19T08:03:37+0000");
  script_tag(name:"last_modification", value:"2024-09-19 08:03:37 +0000 (Thu, 19 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 15:01:04 +0000 (Wed, 04 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-7dc0f381f1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7dc0f381f1");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-7dc0f381f1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310092");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.6' package(s) announced via the FEDORA-2024-7dc0f381f1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-6232 (rhbz#2310092)");

  script_tag(name:"affected", value:"'python3.6' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.6", rpm:"python3.6~3.6.15~36.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.6-debuginfo", rpm:"python3.6-debuginfo~3.6.15~36.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.6-debugsource", rpm:"python3.6-debugsource~3.6.15~36.fc39", rls:"FC39"))) {
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
