# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0621.1");
  script_cve_id("CVE-2015-3197", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:40:14 +0000 (Mon, 07 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0621-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0621-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160621-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968374");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-March/001904.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2016:0621-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl fixes various security issues and bugs:

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

- CVE-2016-0702 aka the 'CacheBleed' attack. (bsc#968050)
 Various changes in the modular exponentation code were added that
 make sure that it is not possible to recover RSA secret keys by
 analyzing cache-bank conflicts on the Intel Sandy-Bridge microarchitecture.

 Note that this was only exploitable if the malicious code was running
 on the same hyper threaded Intel Sandy Bridge processor as the victim
 thread performing decryptions.

- CVE-2016-0705 (bnc#968047):
 A double free() bug in the DSA ASN1 parser code was fixed that could
 be abused to facilitate a denial-of-service attack.

- CVE-2016-0797 (bnc#968048):
 The BN_hex2bn() and BN_dec2bn() functions had a bug that could result
 in an attempt to de-reference a NULL pointer leading to crashes.
 This could have security consequences if these functions were ever
 called by user applications with large untrusted hex/decimal data. Also,
 internal usage of these functions in OpenSSL uses data from config files
 or application command line arguments. If user developed applications
 generated config file data based on untrusted data, then this could
 have had security consequences as well.

- CVE-2016-0798 (bnc#968265)
 The SRP user database lookup method SRP_VBASE_get_by_user() had a memory
 leak that attackers could abuse to facility DoS attacks. To mitigate
 the issue, the seed handling in SRP_VBASE_get_by_user() was disabled
 even if the user has configured a seed. Applications are advised to
 migrate to SRP_VBASE_get1_by_user().

- CVE-2016-0799 (bnc#968374)
 On many 64 bit systems, the internal fmtstr() and doapr_outch()
 functions could miscalculate the length of a string and attempt to
 access out-of-bounds memory locations. These problems could have
 enabled attacks where large amounts of untrusted data is passed to
 the BIO_*printf functions. If applications use these functions in
 this way then they could have been vulnerable. OpenSSL itself uses
 these functions when printing out human-readable dumps of ASN.1
 data. Therefore applications that print this data could have ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssl' package(s) on SUSE Linux Enterprise Server 11.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1-devel", rpm:"libopenssl1-devel~1.0.1g~0.40.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1g~0.40.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1g~0.40.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-x86", rpm:"libopenssl1_0_0-x86~1.0.1g~0.40.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1", rpm:"openssl1~1.0.1g~0.40.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1-doc", rpm:"openssl1-doc~1.0.1g~0.40.1", rls:"SLES11.0"))) {
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
