# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122742");
  script_cve_id("CVE-2014-5355", "CVE-2015-2694");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:19 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2154)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2154");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2154.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2015-2154 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.13.2-9]
- Add patch and test case for 'KDC does not return proper
 client principal for client referrals'
- Resolves: #1259846

[1.13.2-9]
- Amend patch for RedHat bug #1252454 ('testsuite complains
 'Lifetime has increased by 32436 sec while 0 sec passed!',
 while rhel5-libkrb5 passes') to handle the newly introduced
 valgrind hits.

[1.13.2-8]
- Add a patch to fix RH Bug #1250154 ('[s390x, ppc64, ppc64le]:
 kadmind does not accept ACL if kadm5.acl does not end with EOL')
 The code 'accidently' works on x86/AMD64 because declaring a
 variable <pipe>char<pipe> results in an <pipe>unsigned char<pipe> by default while
 most other platforms (e.g. { s390x, ppc64, ppc64le, ...})
 default to <pipe>signed char<pipe> (still have to use lint(1) to clean
 up 38 more instances of this kind of bug).

[1.13.2-7]
- Obsolete multilib versions of server packages to fix RH
 bug #1251913 ('krb5 should obsolete the multilib versions
 of krb5-server and krb5-server-ldap').
 The following packages are declared obsolete:
 - krb5-server-1.11.3-49.el7.i686
 - krb5-server-1.11.3-49.el7.ppc
 - krb5-server-1.11.3-49.el7.s390
 - krb5-server-ldap-1.11.3-49.el7.i686
 - krb5-server-ldap-1.11.3-49.el7.ppc
 - krb5-server-ldap-1.11.3-49.el7.s390

[1.13.2-6]
- Add a patch to fix RedHat bug #1252454 ('testsuite complains
 'Lifetime has increased by 32436 sec while 0 sec passed!',
 while rhel5-libkrb5 passes') so that krb5 resolves GSS creds
 if <pipe>time_rec<pipe> is requested.

[1.13.2-5]
- Add a patch to fix RedHat bug #1251586 ('KDC sends multiple
 requests to ipa-otpd for the same authentication') which causes
 the KDC to send multiple retries to ipa-otpd for TCP transports
 while it should only be done for UDP.

[1.13.2-4]
- the rebase to krb5 1.13.2 in vers 1.13.2-0 also fixed:
 - Redhat Bug #1247761 ('RFE: Minor krb5 spec file cleanup and sync
 with recent Fedora 22/23 changes')
 - Redhat Bug #1247751 ('krb5-config returns wrong -specs path')
 - Redhat Bug #1247608 ('Add support for multi-hop preauth mechs
 via <pipe>KDC_ERR_MORE_PREAUTH_DATA_REQUIRED<pipe> for RFC 6113 ('A
 Generalized Framework for Kerberos Pre-Authentication')')
- Removed 'krb5-1.10-kprop-mktemp.patch' and
 'krb5-1.3.4-send-pr-tempfile.patch', both are no longer used since
 the rebase to krb5 1.13.1

[1.13.2-3]
- Add patch to fix Redhat Bug #1222903 ('[SELinux] AVC denials may appear
 when kadmind starts'). The issue was caused by an unneeded <pipe>htons()<pipe>
 which triggered SELinux AVC denials due to the 'random' port usage.

[1.13.2-2]
- Add fix for RedHat Bug #1164304 ('Upstream unit tests loads
 the installed shared libraries instead the ones from the build')

[1.13.2-1]
- the rebase to krb5 1.13.1 in vers 1.13.1-0 also fixed:
 - Bug 1144498 ('Fix the race condition in the libkrb5 replay cache')
 - Bug 1163402 ('kdb5_ldap_util view_policy does not shows ticket flags on s390x and ppc64')
 - Bug 1185770 ('Missing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'krb5' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.13.2~10.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.13.2~10.el7", rls:"OracleLinux7"))) {
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
