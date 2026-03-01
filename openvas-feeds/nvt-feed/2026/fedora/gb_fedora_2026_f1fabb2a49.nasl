# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.102110297989829749");
  script_cve_id("CVE-2026-2100");
  script_tag(name:"creation_date", value:"2026-02-12 04:43:51 +0000 (Thu, 12 Feb 2026)");
  script_version("2026-02-12T05:59:59+0000");
  script_tag(name:"last_modification", value:"2026-02-12 05:59:59 +0000 (Thu, 12 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-f1fabb2a49)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-f1fabb2a49");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-f1fabb2a49");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2383011");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2394340");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437309");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437310");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p11-kit' package(s) announced via the FEDORA-2026-f1fabb2a49 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Notable changes from the rebase:
* pkcs11: Update PKCS11 headers to version 3.2
* rpc: fix NULL dereference via C_DeriveKey with specific NULL parameters (CVE-2026-2100)
* trust: Lookup DNs in reverse order (RFC4514 section 2.1)");

  script_tag(name:"affected", value:"'p11-kit' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw32-p11-kit", rpm:"mingw32-p11-kit~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-p11-kit-debuginfo", rpm:"mingw32-p11-kit-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-p11-kit", rpm:"mingw64-p11-kit~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-p11-kit-debuginfo", rpm:"mingw64-p11-kit-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit", rpm:"p11-kit~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-client", rpm:"p11-kit-client~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-client-debuginfo", rpm:"p11-kit-client-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-debuginfo", rpm:"p11-kit-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-debugsource", rpm:"p11-kit-debugsource~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-devel", rpm:"p11-kit-devel~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-server", rpm:"p11-kit-server~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-server-debuginfo", rpm:"p11-kit-server-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-trust", rpm:"p11-kit-trust~0.26.2~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-trust-debuginfo", rpm:"p11-kit-trust-debuginfo~0.26.2~1.fc43", rls:"FC43"))) {
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
