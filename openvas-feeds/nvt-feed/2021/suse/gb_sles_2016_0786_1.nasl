# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0786.1");
  script_cve_id("CVE-2014-9761", "CVE-2015-0293", "CVE-2015-1819", "CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196", "CVE-2015-3197", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7547", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317", "CVE-2015-8710", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779", "CVE-2016-0702", "CVE-2016-0703", "CVE-2016-0704", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:07 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-07 15:40:14 +0000 (Mon, 07 Mar 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0786-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160786-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sles12-docker-image' package(s) announced via the SUSE-SU-2016:0786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sles12-docker-image fixes issues with binaries and libraries included in the image where security updates have been made available in the last weeks.
glibc security issues fixed:
- CVE-2015-7547: A stack-based buffer overflow in getaddrinfo allowed
 remote attackers to cause a crash or execute arbitrary code via crafted
 and timed DNS responses (bsc#961721)
- CVE-2015-8777: Insufficient checking of LD_POINTER_GUARD environment
 variable allowed local attackers to bypass the pointer guarding
 protection of the dynamic loader on set-user-ID and set-group-ID
 programs (bsc#950944)
- CVE-2015-8776: Out-of-range time values passed to the strftime function
 may cause it to crash, leading to a denial of service, or potentially
 disclosure information (bsc#962736)
- CVE-2015-8778: Integer overflow in hcreate and hcreate_r could have
 caused an out-of-bound memory access. leading to application crashes or,
 potentially, arbitrary code execution (bsc#962737)
- CVE-2014-9761: A stack overflow (unbounded alloca) could have caused
 applications which process long strings with the nan function to crash
 or, potentially, execute arbitrary code. (bsc#962738)
- CVE-2015-8779: A stack overflow (unbounded alloca) in the catopen
 function could have caused applications which pass long strings to the
 catopen function to crash or, potentially execute arbitrary code.
 (bsc#962739)
glibc bugs fixed:
- bsc#955647: Resource leak in resolver
- bsc#956716: Don't do lock elision on an error checking mutex
- bsc#958315: Reinitialize dl_load_write_lock on fork openssl security bugs fixed: Security issues fixed:
- CVE-2016-0800 aka the 'DROWN' attack (bsc#968046): OpenSSL was
 vulnerable to a cross-protocol attack that could lead to decryption of
 TLS sessions by using a server supporting SSLv2 and EXPORT cipher suites
 as a Bleichenbacher RSA padding oracle.
 This update changes the openssl library to:
 * Disable SSLv2 protocol support by default.
 This can be overridden by setting the environment variable
'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options using the SSL_OP_NO_SSLv2 flag.
 Note that various services and clients had already disabled SSL protocol 2 by default previously.
 * Disable all weak EXPORT ciphers by default. These can be re-enabled if
 required by old legacy software using the environment variable
 'OPENSSL_ALLOW_EXPORT'.
- CVE-2016-0702 aka the 'CacheBleed' attack. (bsc#968050) Various changes
 in the modular exponentation code were added that make sure that it is
 not possible to recover RSA secret keys by analyzing cache-bank
 conflicts on the Intel Sandy-Bridge microarchitecture.
 Note that this was only exploitable if the malicious code was running
 on the same hyper threaded Intel Sandy Bridge processor as the victim
 thread performing decryptions.
- CVE-2016-0705 (bnc#968047): A double free() bug in the DSA ASN1 parser
 code was fixed that could be ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sles12-docker-image' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"sles12-docker-image", rpm:"sles12-docker-image~1.1.1~20160307081810", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sles12-docker-image", rpm:"sles12-docker-image~1.1.1~20160307082130", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sles12-docker-image", rpm:"sles12-docker-image~1.1.1~20160307082632", rls:"SLES12.0"))) {
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
