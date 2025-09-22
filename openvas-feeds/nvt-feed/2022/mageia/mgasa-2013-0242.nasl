# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0242");
  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0242.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-bignum-division-by-zero.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/08/06/13");
  script_xref(name:"URL", value:"http://www.search-lab.hu/advisories/secadv-20130722");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10925");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, putty' package(s) announced via the MGASA-2013-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PuTTY versions 0.62 and earlier - as well as all software that
integrates these versions of PuTTY - are vulnerable to an integer
overflow leading to heap overflow during the SSH handshake before
authentication, caused by improper bounds checking of the length
parameter received from the SSH server. This allows remote attackers
to cause denial of service, and may have more severe impact on the
operation of software that uses PuTTY code (CVE-2013-4852).

PuTTY versions 0.62 and earlier - as well as all software that
integrates these versions of PuTTY - are vulnerable to a heap-corrupting
buffer underrun bug in the modmul function which performs modular
multiplication (CVE-2013-4206).

PuTTY versions 0.62 and earlier - as well as all software that
integrates these versions of PuTTY - are vulnerable to a buffer overflow
vulnerability in the calculation of modular inverses when verifying a
DSA signature (CVE-2013-4207).

PuTTY versions 0.62 and earlier - as well as all software that
integrates these versions of PuTTY - are vulnerable to private keys left
in memory after being used by PuTTY tools (CVE-2013-4208).");

  script_tag(name:"affected", value:"'filezilla, putty' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.7.3~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.63~1.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.7.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.63~1.mga3", rls:"MAGEIA3"))) {
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
