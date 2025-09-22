# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0011");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2020-0011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0011");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0011.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25914");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4591");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl' package(s) announced via the MGASA-2020-0011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated cyrus-sasl packages fix security vulnerability:

Stephan Zeisberg reported an out-of-bounds write vulnerability in the
_sasl_add_string() function in cyrus-sasl2, a library implementing the
Simple Authentication and Security Layer. A remote attacker can take
advantage of this issue to cause denial-of-service conditions for
applications using the library (CVE-2019-19906).");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-mysql", rpm:"lib64sasl2-plug-mysql~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-pgsql", rpm:"lib64sasl2-plug-pgsql~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-scram", rpm:"lib64sasl2-plug-scram~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-sqlite3", rpm:"lib64sasl2-plug-sqlite3~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2-plug-srp", rpm:"lib64sasl2-plug-srp~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sasl2_3", rpm:"lib64sasl2_3~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-mysql", rpm:"libsasl2-plug-mysql~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-pgsql", rpm:"libsasl2-plug-pgsql~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-scram", rpm:"libsasl2-plug-scram~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-sqlite3", rpm:"libsasl2-plug-sqlite3~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-plug-srp", rpm:"libsasl2-plug-srp~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2_3", rpm:"libsasl2_3~2.1.27~1.1.mga7", rls:"MAGEIA7"))) {
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
