# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0037");
  script_tag(name:"creation_date", value:"2024-02-15 04:11:57 +0000 (Thu, 15 Feb 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0037");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0037.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32844");
  script_xref(name:"URL", value:"https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-2.28.5");
  script_xref(name:"URL", value:"https://github.com/Mbed-TLS/mbedtls/releases/tag/v2.28.4");
  script_xref(name:"URL", value:"https://github.com/Mbed-TLS/mbedtls/releases/tag/v2.28.5");
  script_xref(name:"URL", value:"https://github.com/Mbed-TLS/mbedtls/releases/tag/v2.28.6");
  script_xref(name:"URL", value:"https://github.com/Mbed-TLS/mbedtls/releases/tag/v2.28.7");
  script_xref(name:"URL", value:"https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2023-10-1/");
  script_xref(name:"URL", value:"https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2024-01-1/");
  script_xref(name:"URL", value:"https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2024-01-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls' package(s) announced via the MGASA-2024-0037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update brings the mbedtls packages from 2.28.3 to the latest 2.28.7
release in the LTS branch, fixing a number of bugs as well the following
security vulnerabilities:
- Buffer overread in TLS stream cipher suites.
- Timing side channel in private key RSA operations.
- Buffer overflow in mbedtls_x509_set_extension.
See the linked release notes for details.");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedcrypto7", rpm:"lib64mbedcrypto7~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls-devel", rpm:"lib64mbedtls-devel~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls14", rpm:"lib64mbedtls14~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedx509_1", rpm:"lib64mbedx509_1~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedcrypto7", rpm:"libmbedcrypto7~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls-devel", rpm:"libmbedtls-devel~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls14", rpm:"libmbedtls14~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedx509_1", rpm:"libmbedx509_1~2.28.7~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~2.28.7~1.mga9", rls:"MAGEIA9"))) {
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
