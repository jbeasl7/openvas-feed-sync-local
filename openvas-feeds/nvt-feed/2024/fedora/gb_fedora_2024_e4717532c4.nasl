# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886694");
  script_tag(name:"creation_date", value:"2024-05-27 10:50:45 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e4717532c4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e4717532c4");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e4717532c4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281417");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2281577");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crosswords, libipuz' package(s) announced via the FEDORA-2024-e4717532c4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"crosswords 0.3.13");

  script_tag(name:"affected", value:"'crosswords, libipuz' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"crossword-editor", rpm:"crossword-editor~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crossword-editor-debuginfo", rpm:"crossword-editor-debuginfo~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords", rpm:"crosswords~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-debuginfo", rpm:"crosswords-debuginfo~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-debugsource", rpm:"crosswords-debugsource~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-doc", rpm:"crosswords-doc~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-puzzle-sets-cats-and-dogs", rpm:"crosswords-puzzle-sets-cats-and-dogs~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-puzzle-sets-internal", rpm:"crosswords-puzzle-sets-internal~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-thumbnailer", rpm:"crosswords-thumbnailer~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crosswords-thumbnailer-debuginfo", rpm:"crosswords-thumbnailer-debuginfo~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipuz-convertor", rpm:"ipuz-convertor~0.3.13~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz", rpm:"libipuz~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-debuginfo", rpm:"libipuz-debuginfo~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-debugsource", rpm:"libipuz-debugsource~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-devel", rpm:"libipuz-devel~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-doc", rpm:"libipuz-doc~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-tests", rpm:"libipuz-tests~0.4.6.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipuz-tests-debuginfo", rpm:"libipuz-tests-debuginfo~0.4.6.2~1.fc40", rls:"FC40"))) {
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
