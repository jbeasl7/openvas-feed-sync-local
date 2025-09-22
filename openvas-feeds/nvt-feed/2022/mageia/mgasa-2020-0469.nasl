# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0469");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2020-0469)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0469");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0469.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27869");
  script_xref(name:"URL", value:"https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.9");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls' package(s) announced via the MGASA-2020-0469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides security bug fixes and minor enhancements.

Limit the size of calculations performed by mbedtls_mpi_exp_mod to
MBEDTLS_MPI_MAX_SIZE to prevent a potential denial of service when generating
Diffie-Hellman key pairs.

A failure of the random generator was ignored in mbedtls_mpi_fill_random(),
which is how most uses of randomization in asymmetric cryptography are
implemented. This could cause failures or the silent use of non-random values.

Fix a compliance issue whereby the library did not check the tag on the
algorithm parameters (only the size) when comparing the signature in the
description part of the cert to the real signature.

Zeroising of local buffers and variables which are used for calculations in
mbedtls_pkcs5_pbkdf2_hmac(), mbedtls_internal_sha*_process(),
mbedtls_internal_md*_process() and mbedtls_internal_ripemd160_process()
functions to erase sensitive data from memory.");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedcrypto3", rpm:"lib64mbedcrypto3~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls-devel", rpm:"lib64mbedtls-devel~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls12", rpm:"lib64mbedtls12~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedx509_0", rpm:"lib64mbedx509_0~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedcrypto3", rpm:"libmbedcrypto3~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls-devel", rpm:"libmbedtls-devel~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls12", rpm:"libmbedtls12~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedx509_0", rpm:"libmbedx509_0~2.16.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~2.16.9~1.mga7", rls:"MAGEIA7"))) {
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
