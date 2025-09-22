# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131244");
  script_cve_id("CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799");
  script_tag(name:"creation_date", value:"2016-03-03 12:39:15 +0000 (Thu, 03 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:40:14 +0000 (Mon, 07 Mar 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0093.html");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv/20160301.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17859");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3500");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2016-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update openssl packages fix security vulnerabilities:

Yuval Yarom from the University of Adelaide and NICTA, Daniel Genkin from
Technion and Tel Aviv University, and Nadia Heninger from the University of
Pennsylvania discovered a side-channel attack which makes use of cache-bank
conflicts on the Intel Sandy-Bridge microarchitecture. This could allow local
attackers to recover RSA private keys (CVE-2016-0702).

Adam Langley from Google discovered a double free bug when parsing malformed
DSA private keys. This could allow remote attackers to cause a denial of
service or memory corruption in applications parsing DSA private keys
received from untrusted sources (CVE-2016-0705).

Guido Vranken discovered an integer overflow in the BN_hex2bn and BN_dec2bn
functions that can lead to a NULL pointer dereference and heap corruption.
This could allow remote attackers to cause a denial of service or memory
corruption in applications processing hex or dec data received from untrusted
sources (CVE-2016-0797).

Emilia Kasper of the OpenSSL development team discovered a memory leak in the
SRP database lookup code. To mitigate the memory leak, the seed handling in
SRP_VBASE_get_by_user is now disabled even if the user has configured a seed.
Applications are advised to migrate to the SRP_VBASE_get1_by_user function
(CVE-2016-0798).

Guido Vranken discovered an integer overflow in the BIO_*printf functions
that could lead to an OOB read when printing very long strings. Additionally
the internal doapr_outch function can attempt to write to an arbitrary memory
location in the event of a memory allocation failure. These issues will only
occur on platforms where sizeof(size_t) > sizeof(int) like many 64 bit
systems. This could allow remote attackers to cause a denial of service or
memory corruption in applications that pass large amounts of untrusted data
to the BIO_*printf functions (CVE-2016-0799).

Note that Mageia is not vulnerable to the DROWN issue, also known as
CVE-2016-0800, in its default configuration, as SSLv2 was disabled by
default in Mageia 5. However, upstream mitigations for DROWN have also been
incorporated into this update, protecting systems that may have enabled it.");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.2g~1.1.mga5", rls:"MAGEIA5"))) {
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
