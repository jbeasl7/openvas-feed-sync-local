# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131231");
  script_cve_id("CVE-2015-7511");
  script_tag(name:"creation_date", value:"2016-02-18 05:27:38 +0000 (Thu, 18 Feb 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-21 16:27:35 +0000 (Thu, 21 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0072");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0072.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2015-09/msg00033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16806");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17742");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3474");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt' package(s) announced via the MGASA-2016-0072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libgcrypt packages fix security vulnerability:

Daniel Genkin, Lev Pachmanov, Itamar Pipman and Eran Tromer discovered that
the ECDH secret decryption keys in applications using the libgcrypt20 library
could be leaked via a side-channel attack (CVE-2015-7511).

The libgcrypt package was also updated to include countermeasures against
Lenstra's fault attack on RSA Chinese Remainder Theorem optimization in RSA.
A signature verification step was updated to protect against leaks of private
keys in case of hardware faults or implementation errors in numeric
libraries. This issue is equivalent to the CVE-2015-5738 issue in gnupg.");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt-devel", rpm:"lib64gcrypt-devel~1.5.4~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gcrypt11", rpm:"lib64gcrypt11~1.5.4~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt", rpm:"libgcrypt~1.5.4~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.5.4~5.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt11", rpm:"libgcrypt11~1.5.4~5.2.mga5", rls:"MAGEIA5"))) {
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
