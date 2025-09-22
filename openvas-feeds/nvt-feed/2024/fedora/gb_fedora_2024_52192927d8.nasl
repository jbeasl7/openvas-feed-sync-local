# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887347");
  script_cve_id("CVE-2024-29506", "CVE-2024-29507", "CVE-2024-29508", "CVE-2024-29509", "CVE-2024-33869");
  script_tag(name:"creation_date", value:"2024-08-06 07:34:29 +0000 (Tue, 06 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-02 20:10:32 +0000 (Fri, 02 Aug 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-52192927d8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-52192927d8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-52192927d8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293958");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295626");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295627");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295628");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295647");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295697");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295700");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295703");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295704");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2296285");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the FEDORA-2024-52192927d8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-33869

----

Security fixes for CVE-2024-29509, CVE-2024-29508, CVE-2024-29507, CVE-2024-29506");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-gtk-debuginfo", rpm:"ghostscript-gtk-debuginfo~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-dvipdf", rpm:"ghostscript-tools-dvipdf~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-fonts", rpm:"ghostscript-tools-fonts~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-tools-printing", rpm:"ghostscript-tools-printing~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs", rpm:"libgs~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-debuginfo", rpm:"libgs-debuginfo~10.02.1~7.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~10.02.1~7.fc39", rls:"FC39"))) {
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
