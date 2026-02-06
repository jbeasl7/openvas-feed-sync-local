# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.1005990097447102");
  script_cve_id("CVE-2026-24882");
  script_tag(name:"creation_date", value:"2026-02-05 04:37:32 +0000 (Thu, 05 Feb 2026)");
  script_version("2026-02-05T05:56:23+0000");
  script_tag(name:"last_modification", value:"2026-02-05 05:56:23 +0000 (Thu, 05 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-d5c00a447f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-d5c00a447f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-d5c00a447f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433665");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2' package(s) announced via the FEDORA-2026-d5c00a447f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix CVE-2026-24882: Stack-based buffer overflow in tpm2daemon allows arbitrary code execution");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-debuginfo", rpm:"gnupg2-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-debugsource", rpm:"gnupg2-debugsource~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-dirmngr", rpm:"gnupg2-dirmngr~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-dirmngr-debuginfo", rpm:"gnupg2-dirmngr-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-g13", rpm:"gnupg2-g13~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-g13-debuginfo", rpm:"gnupg2-g13-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-gpg-agent", rpm:"gnupg2-gpg-agent~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-gpg-agent-debuginfo", rpm:"gnupg2-gpg-agent-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-gpgconf", rpm:"gnupg2-gpgconf~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-gpgconf-debuginfo", rpm:"gnupg2-gpgconf-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-keyboxd", rpm:"gnupg2-keyboxd~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-keyboxd-debuginfo", rpm:"gnupg2-keyboxd-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-scdaemon", rpm:"gnupg2-scdaemon~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-scdaemon-debuginfo", rpm:"gnupg2-scdaemon-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-smime", rpm:"gnupg2-smime~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-smime-debuginfo", rpm:"gnupg2-smime-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-utils", rpm:"gnupg2-utils~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-utils-debuginfo", rpm:"gnupg2-utils-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-verify", rpm:"gnupg2-verify~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-verify-debuginfo", rpm:"gnupg2-verify-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-wks", rpm:"gnupg2-wks~2.4.9~5.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnupg2-wks-debuginfo", rpm:"gnupg2-wks-debuginfo~2.4.9~5.fc43", rls:"FC43"))) {
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
