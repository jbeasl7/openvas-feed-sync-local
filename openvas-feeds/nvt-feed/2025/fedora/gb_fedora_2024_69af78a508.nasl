# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.69971027897508");
  script_cve_id("CVE-2024-46951", "CVE-2024-46952", "CVE-2024-46953", "CVE-2024-46954", "CVE-2024-46955", "CVE-2024-46956");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-14 20:39:54 +0000 (Thu, 14 Nov 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-69af78a508)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-69af78a508");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-69af78a508");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325041");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325042");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325043");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325044");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325045");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325047");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325238");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325241");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the FEDORA-2024-69af78a508 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2024-46951 ghostscript: Arbitrary Code Execution in Artifex Ghostscript Pattern Color Space (fedora#2325238)

2325241 - CVE-2024-46952 CVE-2024-46953 CVE-2024-46954 CVE-2024-46955 CVE-2024-46956 ghostscript: various flaws [fedora-41]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk-debuginfo", rpm:"ghostscript-gtk-debuginfo~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-dvipdf", rpm:"ghostscript-tools-dvipdf~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-fonts", rpm:"ghostscript-tools-fonts~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-printing", rpm:"ghostscript-tools-printing~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs", rpm:"libgs~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-debuginfo", rpm:"libgs-debuginfo~10.03.1~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.03.1~4.fc41", rls:"FC41"))) {
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
