# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0641.1");
  script_cve_id("CVE-2015-0293", "CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:40:14 +0000 (Mon, 07 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0641-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0641-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160641-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968374");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-March/001911.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2016:0641-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for compat-openssl098 fixes various security issues and bugs:

Security issues fixed:
- CVE-2016-0800 aka the 'DROWN' attack (bsc#968046):
 OpenSSL was vulnerable to a cross-protocol attack that could lead to
 decryption of TLS sessions by using a server supporting SSLv2 and
 EXPORT cipher suites as a Bleichenbacher RSA padding oracle.

 This update changes the openssl library to:

 * Disable SSLv2 protocol support by default.

 This can be overridden by setting the environment variable
 'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options using the
 SSL_OP_NO_SSLv2 flag.

 Note that various services and clients had already disabled SSL
 protocol 2 by default previously.

 * Disable all weak EXPORT ciphers by default. These can be re-enabled
 if required by old legacy software using the environment variable
 'OPENSSL_ALLOW_EXPORT'.

- CVE-2016-0797 (bnc#968048):
 The BN_hex2bn() and BN_dec2bn() functions had a bug that could result
 in an attempt to de-reference a NULL pointer leading to crashes.
 This could have security consequences if these functions were ever
 called by user applications with large untrusted hex/decimal data. Also,
 internal usage of these functions in OpenSSL uses data from config files
 or application command line arguments. If user developed applications
 generated config file data based on untrusted data, then this could
 have had security consequences as well.

- CVE-2016-0799 (bnc#968374)
 On many 64 bit systems, the internal fmtstr() and doapr_outch()
 functions could miscalculate the length of a string and attempt to
 access out-of-bounds memory locations. These problems could have
 enabled attacks where large amounts of untrusted data is passed to
 the BIO_*printf functions. If applications use these functions in
 this way then they could have been vulnerable. OpenSSL itself uses
 these functions when printing out human-readable dumps of ASN.1
 data. Therefore applications that print this data could have been
 vulnerable if the data is from untrusted sources. OpenSSL command line
 applications could also have been vulnerable when they print out ASN.1
 data, or if untrusted data is passed as command line arguments. Libssl
 is not considered directly vulnerable.

- CVE-2015-3197 (bsc#963415):
 The SSLv2 protocol did not block disabled ciphers.

Note that the March 1st 2016 release also references following CVEs that were fixed by us with CVE-2015-0293 in 2015:

- CVE-2016-0703 (bsc#968051): This issue only affected versions of
 OpenSSL prior to March 19th 2015 at which time the code was refactored
 to address vulnerability CVE-2015-0293. It would have made the above
 'DROWN' attack much easier.
- CVE-2016-0704 (bsc#968053): 'Bleichenbacher oracle in SSLv2'
 This issue only affected versions of OpenSSL prior to March 19th
 2015 at which time the code was refactored to address vulnerability
 CVE-2015-0293. It would have made the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl098-debugsource", rpm:"compat-openssl098-debugsource~0.9.8j~94.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~94.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~94.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8j~94.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8j~94.1", rls:"SLES12.0"))) {
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
