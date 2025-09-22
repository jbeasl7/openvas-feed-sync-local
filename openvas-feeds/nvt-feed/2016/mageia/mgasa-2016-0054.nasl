# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131224");
  script_cve_id("CVE-2015-5291", "CVE-2015-8036");
  script_tag(name:"creation_date", value:"2016-02-11 05:22:22 +0000 (Thu, 11 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2016-0054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0054");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0054.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17187");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-June/159916.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-October/169765.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175762.html");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-1.3.10-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-1.3.11-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-2.1.1-and-1.3.13-and-polarssl-1.2.16-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-2.1.2-and-1.3.14-and-polarssl-1.2.17-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-2.2.0-2.1.3-1.3.15-and-polarssl.1.2.18-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-2.2.1-2.1.4-1.3.16-and-polarssl.1.2.19-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/polarssl-1.2.15-and-mbedtls-1.3.12-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2015-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'belle-sip, hiawatha, linphone, mbedtls, pdns' package(s) announced via the MGASA-2016-0054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Note: this package was called polarssl, but is now called mbed tls. The
PolarSSL software is now called mbed TLS.

Heap-based buffer overflow in mbed TLS (formerly PolarSSL) 1.3.x before
1.3.14 allows remote SSL servers to cause a denial of service
(client crash) and possibly execute arbitrary code via a long hostname to
the server name indication (SNI) extension, which is not properly handled
when creating a ClientHello message (CVE-2015-5291).

Heap-based buffer overflow in mbed TLS (formerly PolarSSL) 1.3.x before
1.3.14 allows remote SSL servers to cause a denial of service
(client crash) and possibly execute arbitrary code via a long session
ticket name to the session ticket extension, which is not properly
handled when creating a ClientHello message to resume a session
(CVE-2015-8036).

The mbedtls package has been updated to version 1.3.16, which contains
several other bug fixes, security fixes, and security enhancements.

The hiawatha package, which uses the polarssl/mbedtls library, has been
updated to version 9.13 for improved compatibility.

The belle-sip library package has been updated to version 1.4.2 for
improved compatibility and the linphone package has been rebuilt against
mbedtls.

The pdns package has also been rebuilt against mbedtls.");

  script_tag(name:"affected", value:"'belle-sip, hiawatha, linphone, mbedtls, pdns' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"belle-sip", rpm:"belle-sip~1.4.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hiawatha", rpm:"hiawatha~9.13~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bellesip-devel", rpm:"lib64bellesip-devel~1.4.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bellesip0", rpm:"lib64bellesip0~1.4.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64linphone-devel", rpm:"lib64linphone-devel~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64linphone6", rpm:"lib64linphone6~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls-devel", rpm:"lib64mbedtls-devel~1.3.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls9", rpm:"lib64mbedtls9~1.3.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mediastreamer4", rpm:"lib64mediastreamer4~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbellesip-devel", rpm:"libbellesip-devel~1.4.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbellesip0", rpm:"libbellesip0~1.4.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblinphone-devel", rpm:"liblinphone-devel~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblinphone6", rpm:"liblinphone6~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls-devel", rpm:"libmbedtls-devel~1.3.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls9", rpm:"libmbedtls9~1.3.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmediastreamer4", rpm:"libmediastreamer4~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linphone", rpm:"linphone~3.8.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~1.3.16~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns", rpm:"pdns~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-geo", rpm:"pdns-backend-geo~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-ldap", rpm:"pdns-backend-ldap~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-mysql", rpm:"pdns-backend-mysql~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pgsql", rpm:"pdns-backend-pgsql~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-pipe", rpm:"pdns-backend-pipe~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pdns-backend-sqlite", rpm:"pdns-backend-sqlite~3.3.3~1.1.mga5", rls:"MAGEIA5"))) {
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
