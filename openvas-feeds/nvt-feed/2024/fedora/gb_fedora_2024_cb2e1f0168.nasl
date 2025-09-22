# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.9998210111020168");
  script_cve_id("CVE-2024-47191");
  script_tag(name:"creation_date", value:"2024-10-21 04:08:33 +0000 (Mon, 21 Oct 2024)");
  script_version("2024-10-22T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-cb2e1f0168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-cb2e1f0168");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-cb2e1f0168");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316447");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316488");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2316493");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oath-toolkit' package(s) announced via the FEDORA-2024-cb2e1f0168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is new version fixing possible local privilege escalation.");

  script_tag(name:"affected", value:"'oath-toolkit' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"liboath", rpm:"liboath~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath-debuginfo", rpm:"liboath-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath-devel", rpm:"liboath-devel~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath-doc", rpm:"liboath-doc~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc", rpm:"libpskc~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc-debuginfo", rpm:"libpskc-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc-devel", rpm:"libpskc-devel~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpskc-doc", rpm:"libpskc-doc~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit", rpm:"oath-toolkit~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit-debuginfo", rpm:"oath-toolkit-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit-debugsource", rpm:"oath-toolkit-debugsource~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oathtool", rpm:"oathtool~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oathtool-debuginfo", rpm:"oathtool-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_oath", rpm:"pam_oath~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_oath-debuginfo", rpm:"pam_oath-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pskctool", rpm:"pskctool~2.6.12~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pskctool-debuginfo", rpm:"pskctool-debuginfo~2.6.12~1.fc40", rls:"FC40"))) {
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
