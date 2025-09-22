# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0395");
  script_cve_id("CVE-2017-15361");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-08 15:19:48 +0000 (Wed, 08 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0395)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0395");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0395.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21944");
  script_xref(name:"URL", value:"https://www.politsei.ee/en/uudised/uudis.dot?id=785151");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrome-token-signing, libdigidocpp, opensc, qdigidoc, qesteidutil, task-esteid' package(s) announced via the MGASA-2017-0395 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability, dubbed ROCA, was identified in an implementation of
RSA key generation due to a fault in a code library developed by
Infineon Technologies. The affected encryption keys are used to secure
many forms of technology, such as hardware chips, authentication tokens,
software packages, electronic documents, TLS/HTTPS keys, and PGP.
Infineon Technologies' smartcards, security tokens, and secure hardware
chips produced since 2012 use the affected code library. Successful
exploitation of this vulnerability results in an attacker being able to
derive a private key from the public key, using prime factorization,
within a practical time frame.

This vulnerability does not affect the RSA encryption algorithm itself,
and only affects the implementation of the RSA encryption by Infineon
Technologies.

This vulnerability also affects Estonian ID cards that were issued after
16th October 2014. With the updated packages the user is able to update
his/her certificates and continue using the online services that require
ID card.");

  script_tag(name:"affected", value:"'chrome-token-signing, libdigidocpp, opensc, qdigidoc, qesteidutil, task-esteid' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"chrome-token-signing", rpm:"chrome-token-signing~1.0.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digidocpp-devel", rpm:"lib64digidocpp-devel~3.13.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64digidocpp1", rpm:"lib64digidocpp1~3.13.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc-devel", rpm:"lib64opensc-devel~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64opensc3", rpm:"lib64opensc3~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smm-local3", rpm:"lib64smm-local3~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidocpp", rpm:"libdigidocpp~3.13.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidocpp-devel", rpm:"libdigidocpp-devel~3.13.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdigidocpp1", rpm:"libdigidocpp1~3.13.2~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc-devel", rpm:"libopensc-devel~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopensc3", rpm:"libopensc3~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmm-local3", rpm:"libsmm-local3~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.15.0~2.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qdigidoc", rpm:"qdigidoc~3.13.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qdigidoc-nautilus", rpm:"qdigidoc-nautilus~3.13.3~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qesteidutil", rpm:"qesteidutil~3.12.7~2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"task-esteid", rpm:"task-esteid~3.13.3~1.mga6", rls:"MAGEIA6"))) {
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
