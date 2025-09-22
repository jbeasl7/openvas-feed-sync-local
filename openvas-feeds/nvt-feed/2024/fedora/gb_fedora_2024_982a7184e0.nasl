# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886750");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460", "CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661", "CVE-2024-32662");
  script_tag(name:"creation_date", value:"2024-05-27 10:46:20 +0000 (Mon, 27 May 2024)");
  script_version("2025-02-05T05:38:26+0000");
  script_tag(name:"last_modification", value:"2025-02-05 05:38:26 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:44:06 +0000 (Tue, 04 Feb 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-982a7184e0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-982a7184e0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-982a7184e0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276721");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276722");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276724");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276725");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276726");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276736");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276740");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276744");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276751");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276757");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276760");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276804");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276809");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276961");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276967");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276968");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276970");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276971");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276976");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276982");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2276988");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp2' package(s) announced via the FEDORA-2024-982a7184e0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.11.7 (CVE-2024-32039, CVE-2024-32040, CVE-2024-32041, CVE-2024-32458, CVE-2024-32459, CVE-2024-32460, CVE-2024-32658, CVE-2024-32659, CVE-2024-32660, CVE-2024-32661, CVE-2024-32662)");

  script_tag(name:"affected", value:"'freerdp2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp2", rpm:"freerdp2~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp2-debuginfo", rpm:"freerdp2-debuginfo~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp2-debugsource", rpm:"freerdp2-debugsource~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp2-devel", rpm:"freerdp2-devel~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp2-libs", rpm:"freerdp2-libs~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp2-libs-debuginfo", rpm:"freerdp2-libs-debuginfo~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.11.7~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-devel", rpm:"libwinpr2-devel~2.11.7~1.fc40", rls:"FC40"))) {
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
