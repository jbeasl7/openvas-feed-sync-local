# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.97998100481015897");
  script_cve_id("CVE-2024-11858");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-08-06T05:45:41+0000");
  script_tag(name:"last_modification", value:"2025-08-06 05:45:41 +0000 (Wed, 06 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-05 17:56:17 +0000 (Tue, 05 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2024-ac8d48e58a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ac8d48e58a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ac8d48e58a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2313891");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327286");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2327308");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329104");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329105");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329107");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329108");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329622");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2329623");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iaito, radare2' package(s) announced via the FEDORA-2024-ac8d48e58a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bump radare2 to 5.9.8, iaito to 5.9.9, fixes CVE-2024-11858");

  script_tag(name:"affected", value:"'iaito, radare2' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"iaito", rpm:"iaito~5.9.9~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debuginfo", rpm:"iaito-debuginfo~5.9.9~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debugsource", rpm:"iaito-debugsource~5.9.9~2.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.8~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-common", rpm:"radare2-common~5.9.8~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debuginfo", rpm:"radare2-debuginfo~5.9.8~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debugsource", rpm:"radare2-debugsource~5.9.8~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.8~4.fc41", rls:"FC41"))) {
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
