# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1859.1");
  script_cve_id("CVE-2019-12904");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-24 11:49:45 +0000 (Mon, 24 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1859-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191859-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt' package(s) announced via the SUSE-SU-2019:1859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgcrypt fixes the following issues:

Security issues fixed:
CVE-2019-12904: The C implementation of AES is vulnerable to a
 flush-and-reload side-channel attack because physical addresses are
 available to other processes. (The C implementation is used on platforms
 where an assembly-language implementation is unavailable.) (bsc#1138939)

Other bugfixes:
Don't run full FIPS self-tests from constructor (bsc#1097073)

Skip all the self-tests except for binary integrity when called from the
 constructor (bsc#1097073)

Enforce the minimal RSA keygen size in fips mode (bsc#1125740)

avoid executing some tests twice.

Fixed a race condition in initialization.

Fixed env-script-interpreter in cavs_driver.pl

Fixed redundant fips tests in some situations causing failure to boot in
 fips mode. (bsc#1097073)

This helps during booting of the system in FIPS mode with insufficient entropy.");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-debugsource", rpm:"libgcrypt-debugsource~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel", rpm:"libgcrypt-devel~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt-devel-debuginfo", rpm:"libgcrypt-devel-debuginfo~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20", rpm:"libgcrypt20~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit", rpm:"libgcrypt20-32bit~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit-debuginfo", rpm:"libgcrypt20-32bit-debuginfo~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-debuginfo", rpm:"libgcrypt20-debuginfo~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac", rpm:"libgcrypt20-hmac~1.8.2~6.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac-32bit", rpm:"libgcrypt20-hmac-32bit~1.8.2~6.17.1", rls:"SLES15.0"))) {
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
