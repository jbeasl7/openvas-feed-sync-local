# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.121020999797904");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-12f0caa904)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-12f0caa904");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-12f0caa904");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-sequoia-chameleon-gnupg, rust-sequoia-gpg-agent, rust-sequoia-keystore, rust-sequoia-openpgp, rust-sequoia-sq' package(s) announced via the FEDORA-2024-12f0caa904 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the sequoia-openpgp crate to version 1.21.1. Addresses RUSTSEC-2024-0345.
- Update the sequoia-keystore crate to version 0.5.1.
- Update the sequoia-gpg-agent crate to version 0.4.2.

This update also includes rebuilds of all affected applications that are affected by RUSTSEC-2024-0345 and a regression in sequoia-openpgp 1.21.0.");

  script_tag(name:"affected", value:"'rust-sequoia-chameleon-gnupg, rust-sequoia-gpg-agent, rust-sequoia-keystore, rust-sequoia-openpgp, rust-sequoia-sq' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg", rpm:"rust-sequoia-chameleon-gnupg~0.10.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-chameleon-gnupg-debugsource", rpm:"rust-sequoia-chameleon-gnupg-debugsource~0.10.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-gpg-agent+default-devel", rpm:"rust-sequoia-gpg-agent+default-devel~0.4.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-gpg-agent", rpm:"rust-sequoia-gpg-agent~0.4.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-gpg-agent-devel", rpm:"rust-sequoia-gpg-agent-devel~0.4.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore+default-devel", rpm:"rust-sequoia-keystore+default-devel~0.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore+gpg-agent-devel", rpm:"rust-sequoia-keystore+gpg-agent-devel~0.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore+softkeys-devel", rpm:"rust-sequoia-keystore+softkeys-devel~0.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore", rpm:"rust-sequoia-keystore~0.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-keystore-devel", rpm:"rust-sequoia-keystore-devel~0.5.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+__implicit-crypto-backend-for-tests-devel", rpm:"rust-sequoia-openpgp+__implicit-crypto-backend-for-tests-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+allow-experimental-crypto-devel", rpm:"rust-sequoia-openpgp+allow-experimental-crypto-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+allow-variable-time-crypto-devel", rpm:"rust-sequoia-openpgp+allow-variable-time-crypto-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-bzip2-devel", rpm:"rust-sequoia-openpgp+compression-bzip2-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-deflate-devel", rpm:"rust-sequoia-openpgp+compression-deflate-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+compression-devel", rpm:"rust-sequoia-openpgp+compression-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-nettle-devel", rpm:"rust-sequoia-openpgp+crypto-nettle-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-openssl-devel", rpm:"rust-sequoia-openpgp+crypto-openssl-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+crypto-rust-devel", rpm:"rust-sequoia-openpgp+crypto-rust-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp+default-devel", rpm:"rust-sequoia-openpgp+default-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp", rpm:"rust-sequoia-openpgp~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-openpgp-devel", rpm:"rust-sequoia-openpgp-devel~1.21.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq", rpm:"rust-sequoia-sq~0.37.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-sequoia-sq-debugsource", rpm:"rust-sequoia-sq-debugsource~0.37.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg", rpm:"sequoia-chameleon-gnupg~0.10.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-chameleon-gnupg-debuginfo", rpm:"sequoia-chameleon-gnupg-debuginfo~0.10.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq", rpm:"sequoia-sq~0.37.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sequoia-sq-debuginfo", rpm:"sequoia-sq-debuginfo~0.37.0~3.fc40", rls:"FC40"))) {
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
