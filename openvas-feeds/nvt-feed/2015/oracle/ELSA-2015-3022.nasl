# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123140");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293");
  script_tag(name:"creation_date", value:"2015-10-06 06:48:24 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-3022)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3022");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-fips' package(s) announced via the ELSA-2015-3022 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.1m-2.0.1]
- update to upstream 1.0.1m
- update to fips canister 2.0.9
- regenerated below patches
 openssl-1.0.1-beta2-rpmbuild.patch
 openssl-1.0.1m-rhcompat.patch
 openssl-1.0.1m-ecc-suiteb.patch
 openssl-1.0.1m-fips-mode.patch
 openssl-1.0.1m-version.patch
 openssl-1.0.1m-evp-devel.patch

[1.0.1j-2.0.4]
- [Orabug 20182267] The openssl-fips-devel package should Provide:
 openssl-devel and openssl-devel(x86-64) like the standard -devel
 package
- The openssl-fips-devel package should include fips.h and fips_rand.h
 for apps that want to build against FIPS* APIs

[1.0.1j-2.0.3]
- [Orabug 20086847] reintroduce patch openssl-1.0.1e-ecc-suiteb.patch,
 update ec_curve.c which gets copied into build tree to match the patch
 (ie only have curves which are advertised). The change items from the
 original patch are as follows:
- do not advertise ECC curves we do not support
- fix CPU identification on Cyrix CPUs

[1.0.1j-2.0.2]
- update README.FIPS with step-by-step install instructions

[1.0.1j-2.0.1]
- update to upstream 1.0.1j
- change name to openssl-fips
- change Obsoletes: openssl to Conflicts: openssl
- add Provides: openssl

[1.0.1i-2.0.3.fips]
- update to fips canister 2.0.8 to remove Dual EC DRBG
- run gcc -v so the gcc build version is captured in the build log

[1.0.1i-2.0.2.fips]
- flip EVP_CIPH_* flag bits for compatibility with original RH patched pkg

[1.0.1i-2.0.1.fips]
- build against upstream 1.0.1i
- build against fips validated canister 2.0.7
- add patch to support fips=1
- rename pkg to openssl-fips and Obsolete openssl

[1.0.1e-16.14]
- fix CVE-2010-5298 - possible use of memory after free
- fix CVE-2014-0195 - buffer overflow via invalid DTLS fragment
- fix CVE-2014-0198 - possible NULL pointer dereference
- fix CVE-2014-0221 - DoS from invalid DTLS handshake packet
- fix CVE-2014-0224 - SSL/TLS MITM vulnerability
- fix CVE-2014-3470 - client-side DoS when using anonymous ECDH

[1.0.1e-16.7]
- fix CVE-2014-0160 - information disclosure in TLS heartbeat extension

[1.0.1e-16.4]
- fix CVE-2013-4353 - Invalid TLS handshake crash

[1.0.1e-16.3]
- fix CVE-2013-6450 - possible MiTM attack on DTLS1

[1.0.1e-16.2]
- fix CVE-2013-6449 - crash when version in SSL structure is incorrect

[1.0.1e-16.1]
- add back some no-op symbols that were inadvertently dropped

[1.0.1e-16]
- do not advertise ECC curves we do not support
- fix CPU identification on Cyrix CPUs

[1.0.1e-15]
- make DTLS1 work in FIPS mode
- avoid RSA and DSA 512 bits and Whirlpool in 'openssl speed' in FIPS mode

[1.0.1e-14]
- installation of dracut-fips marks that the FIPS module is installed

[1.0.1e-13]
- avoid dlopening libssl.so from libcrypto

[1.0.1e-12]
- fix small memory leak in FIPS aes selftest
- fix segfault in openssl speed hmac in the FIPS mode

[1.0.1e-11]
- document the nextprotoneg option in manual pages
 original patch by Hubert Kario

[1.0.1e-9]
- always perform the FIPS ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssl-fips' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"openssl-fips", rpm:"openssl-fips~1.0.1m~2.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-fips-devel", rpm:"openssl-fips-devel~1.0.1m~2.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-fips-perl", rpm:"openssl-fips-perl~1.0.1m~2.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-fips-static", rpm:"openssl-fips-static~1.0.1m~2.0.1.el6", rls:"OracleLinux6"))) {
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
