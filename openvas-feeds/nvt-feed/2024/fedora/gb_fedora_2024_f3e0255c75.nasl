# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887238");
  script_cve_id("CVE-2024-34055");
  script_tag(name:"creation_date", value:"2024-06-15 04:08:00 +0000 (Sat, 15 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:16:29 +0000 (Tue, 11 Jun 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-f3e0255c75)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f3e0255c75");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-f3e0255c75");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290510");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2290512");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd' package(s) announced via the FEDORA-2024-f3e0255c75 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Security fix for CVE-2024-34055");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-debuginfo", rpm:"cyrus-imapd-debuginfo~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-debugsource", rpm:"cyrus-imapd-debugsource~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-devel", rpm:"cyrus-imapd-devel~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-doc-extra", rpm:"cyrus-imapd-doc-extra~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-libs", rpm:"cyrus-imapd-libs~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-libs-debuginfo", rpm:"cyrus-imapd-libs-debuginfo~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-utils", rpm:"cyrus-imapd-utils~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-utils-debuginfo", rpm:"cyrus-imapd-utils-debuginfo~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-virusscan", rpm:"cyrus-imapd-virusscan~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-virusscan-debuginfo", rpm:"cyrus-imapd-virusscan-debuginfo~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus", rpm:"perl-Cyrus~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-debuginfo", rpm:"perl-Cyrus-debuginfo~3.8.3~1.fc40", rls:"FC40"))) {
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
