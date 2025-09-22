# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886316");
  script_cve_id("CVE-2023-5992", "CVE-2024-1454");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:57 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-09 01:00:01 +0000 (Fri, 09 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3dbc3e8105)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3dbc3e8105");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3dbc3e8105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2263930");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265003");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the FEDORA-2024-3dbc3e8105 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release with security fixes for CVE-2023-5992 and CVE-2024-1454");

  script_tag(name:"affected", value:"'opensc' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.25.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.25.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.25.0~1.fc40", rls:"FC40"))) {
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
