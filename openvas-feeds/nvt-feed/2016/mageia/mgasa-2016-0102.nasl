# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131253");
  script_cve_id("CVE-2015-5726", "CVE-2015-5727", "CVE-2016-2194", "CVE-2016-2195");
  script_tag(name:"creation_date", value:"2016-03-08 05:15:16 +0000 (Tue, 08 Mar 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-14 01:29:35 +0000 (Sat, 14 May 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0102)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0102");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0102.html");
  script_xref(name:"URL", value:"http://botan.randombit.net/security.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17737");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'botan, monotone, softhsm' package(s) announced via the MGASA-2016-0102 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The BER decoder would crash due to reading from offset 0 of an empty
vector if it encountered a BIT STRING which did not contain any data at
all. This can be used to easily crash applications reading untrusted ASN.1
data, but does not seem exploitable for code execution (CVE-2015-5726).

The BER decoder would allocate a fairly arbitrary amount of memory in a
length field, even if there was no chance the read request would succeed.
This might cause the process to run out of memory or invoke the OOM killer
(CVE-2015-5727).

The ressol function implements the Tonelli-Shanks algorithm for finding
square roots could be sent into a nearly infinite loop due to a misplaced
conditional check. This could occur if a composite modulus is provided, as
this algorithm is only defined for primes. This function is exposed to
attacker controlled input via the OS2ECP function during ECC point
decompression (CVE-2016-2194).

The PointGFp constructor did not check that the affine coordinate
arguments were less than the prime, but then in curve multiplication
assumed that both arguments if multiplied would fit into an integer twice
the size of the prime. The bigint_mul and bigint_sqr functions received
the size of the output buffer, but only used it to dispatch to a faster
algorithm in cases where there was sufficient output space to call an
unrolled multiplication function. The result is a heap overflow accessible
via ECC point decoding, which accepted untrusted inputs. This is likely
exploitable for remote code execution. On systems which use the mlock pool
allocator, it would allow an attacker to overwrite memory held in
secure_vector objects. After this point the write will hit the guard page
at the end of the mmap'ed region so it probably could not be used for code
execution directly, but would allow overwriting adjacent key material
(CVE-2016-2195).");

  script_tag(name:"affected", value:"'botan, monotone, softhsm' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"botan", rpm:"botan~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan-devel", rpm:"lib64botan-devel~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan-static-devel", rpm:"lib64botan-static-devel~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64botan1", rpm:"lib64botan1~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-devel", rpm:"libbotan-devel~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan-static-devel", rpm:"libbotan-static-devel~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbotan1", rpm:"libbotan1~1.10.12~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"monotone", rpm:"monotone~1.1~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"softhsm", rpm:"softhsm~1.3.4~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"softhsm-devel", rpm:"softhsm-devel~1.3.4~5.1.mga5", rls:"MAGEIA5"))) {
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
