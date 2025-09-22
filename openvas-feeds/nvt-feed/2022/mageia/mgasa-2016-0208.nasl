# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0208");
  script_cve_id("CVE-2015-7827", "CVE-2016-2849");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-14 02:30:10 +0000 (Sat, 14 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0208)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0208");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0208.html");
  script_xref(name:"URL", value:"https://botan.randombit.net/security.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18356");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3565");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'botan' package(s) announced via the MGASA-2016-0208 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated botan packages fix security vulnerabilities:

During RSA decryption, how long decoding of PKCS #1 v1.5 padding took was
input dependent. If these differences could be measured by an attacker,
it could be used to mount a Bleichenbacher million-message attack
(CVE-2015-7827).

ECDSA (and DSA) signature algorithms perform a modular inverse on the
signature nonce k. The modular inverse algorithm used had input dependent
loops, and it is possible a side channel attack could recover sufficient
information about the nonce to eventually recover the ECDSA secret key
(CVE-2016-2849).");

  script_tag(name:"affected", value:"'botan' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"botan", rpm:"botan~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan-devel", rpm:"lib64botan-devel~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan-static-devel", rpm:"lib64botan-static-devel~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan1", rpm:"lib64botan1~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-static-devel", rpm:"libbotan-static-devel~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan1", rpm:"libbotan1~1.10.12~1.1.mga5", rls:"MAGEIA5"))) {
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
