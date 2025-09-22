# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0069");
  script_cve_id("CVE-2023-49083", "CVE-2023-50782", "CVE-2024-26130");
  script_tag(name:"creation_date", value:"2025-02-18 04:07:29 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-18T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-02-18 05:38:27 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-05 22:09:20 +0000 (Wed, 05 Feb 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0069)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0069");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0069.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32584");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6673-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6673-3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/29/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl, python-cryptography' package(s) announced via the MGASA-2025-0069 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cryptography vulnerable to NULL-dereference when loading PKCS7
certificates. (CVE-2023-49083)
Python-cryptography: bleichenbacher timing oracle attack against rsa
decryption - incomplete fix for cve-2020-25659. (CVE-2023-50782)
Cryptography NULL pointer deference with
pkcs12.serialize_key_and_certificates when called with a non-matching
certificate and private key and an hmac_hash override. (CVE-2024-26130)");

  script_tag(name:"affected", value:"'openssl, python-cryptography' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl3", rpm:"lib64openssl3~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~3.0.15~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography", rpm:"python-cryptography~39.0.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~39.0.1~1.1.mga9", rls:"MAGEIA9"))) {
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
