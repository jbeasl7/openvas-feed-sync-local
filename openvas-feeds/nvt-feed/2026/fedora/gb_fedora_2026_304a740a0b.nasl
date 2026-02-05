# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.3049774097098");
  script_cve_id("CVE-2025-67897");
  script_tag(name:"creation_date", value:"2026-02-04 04:35:12 +0000 (Wed, 04 Feb 2026)");
  script_version("2026-02-04T05:55:03+0000");
  script_tag(name:"last_modification", value:"2026-02-04 05:55:03 +0000 (Wed, 04 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-304a740a0b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-304a740a0b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-304a740a0b");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2025-0136.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-sequoia-keystore-server, rust-sequoia-octopus-librnp, rust-sequoia-sq, rust-sequoia-sqv' package(s) announced via the FEDORA-2026-304a740a0b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rebuild with sequoia-openpgp v2.1.0 to apply fixes for [RUSTSEC-2025-0136]([link moved to references]) / CVE-2025-67897.");

  script_tag(name:"affected", value:"'rust-sequoia-keystore-server, rust-sequoia-octopus-librnp, rust-sequoia-sq, rust-sequoia-sqv' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore-server", rpm:"rust-sequoia-keystore-server~0.2.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore-server-debugsource", rpm:"rust-sequoia-keystore-server-debugsource~0.2.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp", rpm:"rust-sequoia-octopus-librnp~1.11.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-octopus-librnp-debugsource", rpm:"rust-sequoia-octopus-librnp-debugsource~1.11.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~1.3.1~9.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~1.3.1~9.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv", rpm:"rust-sequoia-sqv~1.3.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sqv-debugsource", rpm:"rust-sequoia-sqv-debugsource~1.3.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keystore-server", rpm:"sequoia-keystore-server~0.2.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-keystore-server-debuginfo", rpm:"sequoia-keystore-server-debuginfo~0.2.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp", rpm:"sequoia-octopus-librnp~1.11.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-octopus-librnp-debuginfo", rpm:"sequoia-octopus-librnp-debuginfo~1.11.1~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~1.3.1~9.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~1.3.1~9.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv", rpm:"sequoia-sqv~1.3.0~5.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sqv-debuginfo", rpm:"sequoia-sqv-debuginfo~1.3.0~5.fc42", rls:"FC42"))) {
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
