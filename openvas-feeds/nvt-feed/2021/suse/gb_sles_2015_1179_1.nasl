# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1179.1");
  script_cve_id("CVE-2014-3591");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-05 18:06:49 +0000 (Thu, 05 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1179-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1179-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151179-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929919");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001473.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgcrypt' package(s) announced via the SUSE-SU-2015:1179-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update of libgcrypt fixes one security issue and brings various FIPS 140-2 related improvements.

libgcrypt now uses ciphertext blinding for Elgamal decryption (CVE-2014-3591)

FIPS 140-2 related changes:
* The library performs its self-tests when the module is complete (the -hmac file is also installed).

* Added a NIST 800-90a compliant DRBG.

* Change DSA key generation to be FIPS 186-4 compliant.

* Change RSA key generation to be FIPS 186-4 compliant.

* Enable HW support in fips mode (bnc#896435)

* Make DSA selftest use 2048 bit keys (bnc#898003)

* Added ECDSA selftests and add support for it to the CAVS testing
 framework (bnc#896202)

* Various CAVS testing improvements.");

  script_tag(name:"affected", value:"'libgcrypt' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20", rpm:"libgcrypt20~1.6.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-32bit", rpm:"libgcrypt20-32bit~1.6.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac", rpm:"libgcrypt20-hmac~1.6.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgcrypt20-hmac-32bit", rpm:"libgcrypt20-hmac-32bit~1.6.1~13.1", rls:"SLES12.0"))) {
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
