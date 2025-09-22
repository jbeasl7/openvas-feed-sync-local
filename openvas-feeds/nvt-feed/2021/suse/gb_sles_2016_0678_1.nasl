# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0678.1");
  script_cve_id("CVE-2015-0287", "CVE-2015-0293", "CVE-2015-3195", "CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0797", "CVE-2016-0799", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:08 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:40:14 +0000 (Mon, 07 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0678-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0678-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160678-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2016:0678-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"OpenSSL was update to fix security issues and bugs:
CVE-2016-0800 aka the 'DROWN' attack (bsc#968046):
OpenSSL was vulnerable to a cross-protocol attack that could lead to decryption of TLS sessions by using a server supporting SSLv2 and EXPORT cipher suites as a Bleichenbacher RSA padding oracle.
This update changes the OpenSSL library to:
Disable SSLv2 protocol support by default.
This can be overridden by setting the environment variable
'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options using the SSL_OP_NO_SSLv2 flag.
Note that various services and clients had already disabled SSL protocol 2 by default previously.
Disable all weak EXPORT ciphers by default. These can be re-enabled if required by old legacy software using the environment variable
'OPENSSL_ALLOW_EXPORT'.
CVE-2016-0797 (bsc#968048):
The BN_hex2bn() and BN_dec2bn() functions had a bug that could result in an attempt to de-reference a NULL pointer leading to crashes.
This could have security consequences if these functions were ever called by user applications with large untrusted hex/decimal data. Also,
internal usage of these functions in OpenSSL uses data from config files or application command line arguments. If user developed applications generated config file data based on untrusted data, then this could have had security consequences as well.
CVE-2016-0799 (bsc#968374):
On many 64 bit systems, the internal fmtstr() and doapr_outch()
functions could miscalculate the length of a string and attempt to access out-of-bounds memory locations. These problems could have enabled attacks where large amounts of untrusted data is passed to the BIO_*printf functions. If applications use these functions in this way then they could have been vulnerable. OpenSSL itself uses these functions when printing out human-readable dumps of ASN.1 data. Therefore applications that print this data could have been vulnerable if the data is from untrusted sources. OpenSSL command line applications could also have been vulnerable when they print out ASN.1 data, or if untrusted data is passed as command line arguments. Libssl is not considered directly vulnerable.
CVE-2015-3197 (bsc#963415):
The SSLv2 protocol did not block disabled ciphers.
CVE-2015-3195 (bsc#957812): An X509_ATTRIBUTE memory leak was fixed.
Fixed a regression caused by the openssl-CVE-2015-0287.patch (bsc#937492)
Note that the March 1st 2016 release also references following CVEs that were fixed by us with CVE-2015-0293 in 2015:
CVE-2016-0703 (bsc#968051): This issue only affected versions of OpenSSL prior to March 19th 2015 at which time the code was refactored to address vulnerability CVE-2015-0293. It would have made the above
'DROWN' attack much easier.
CVE-2016-0704 (bsc#968053): 'Bleichenbacher oracle in SSLv2'
This issue only affected versions of OpenSSL prior to March 19th 2015 at which time the code was refactored to address vulnerability ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8a~18.94.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-32bit", rpm:"openssl-32bit~0.9.8a~18.94.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~0.9.8a~18.94.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-32bit", rpm:"openssl-devel-32bit~0.9.8a~18.94.2", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8a~18.94.2", rls:"SLES10.0SP4"))) {
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
