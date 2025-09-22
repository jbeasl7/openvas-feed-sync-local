# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885477");
  script_cve_id("CVE-2023-40660", "CVE-2023-40661", "CVE-2023-4535");
  script_tag(name:"creation_date", value:"2023-12-23 02:14:54 +0000 (Sat, 23 Dec 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 17:12:25 +0000 (Tue, 14 Nov 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-a854153d7a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-a854153d7a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-a854153d7a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892137");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2191749");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240701");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240912");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240913");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240914");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248092");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248099");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2248101");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the FEDORA-2023-a854153d7a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release (#2240701) with security fixes for CVE-2023-40660, CVE-2023-4535, CVE-2023-40661");

  script_tag(name:"affected", value:"'opensc' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.24.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.24.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.24.0~1.fc39", rls:"FC39"))) {
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
