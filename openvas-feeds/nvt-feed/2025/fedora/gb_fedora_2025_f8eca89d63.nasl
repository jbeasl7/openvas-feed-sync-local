# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.102810199978910063");
  script_cve_id("CVE-2024-56737", "CVE-2025-1744", "CVE-2025-1864", "CVE-2025-56737");
  script_tag(name:"creation_date", value:"2025-03-21 04:05:21 +0000 (Fri, 21 Mar 2025)");
  script_version("2025-07-02T05:41:52+0000");
  script_tag(name:"last_modification", value:"2025-07-02 05:41:52 +0000 (Wed, 02 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-01 14:55:32 +0000 (Tue, 01 Jul 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-f8eca89d63)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f8eca89d63");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f8eca89d63");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334774");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334775");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334777");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2334779");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348976");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348977");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348978");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348979");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349508");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349509");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349510");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349511");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2' package(s) announced via the FEDORA-2025-f8eca89d63 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fix CVE-2024-56737, CVE-2025-56737, CVE-2025-1864

----

Fix CVE-2025-1744 and CVE-2025-1864");

  script_tag(name:"affected", value:"'radare2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.8~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-common", rpm:"radare2-common~5.9.8~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debuginfo", rpm:"radare2-debuginfo~5.9.8~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debugsource", rpm:"radare2-debugsource~5.9.8~7.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.8~7.fc40", rls:"FC40"))) {
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
