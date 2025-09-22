# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123699");
  script_cve_id("CVE-2012-4546");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:24 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2013-0528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0528");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0528.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa' package(s) announced via the ELSA-2013-0528 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.0.0-25.el6]
- Filter generated winbind dependencies so the right version of samba
 can be installed. (#905594)

[3.0.0-24.el6]
- Add certmonger condrestart to server post scriptlet (#903758)
- Make certmonger a (pre) Requires (#903758)
- Add selinux-policy to Requires(pre) to avoid post scriptlet AVCs
 (#903758)
- Set minimum version of pki-ca to 9.0.3-30 and add to Requires(pre)
 to pick up certmonger upgrade fix (#902474)
- Update anonymous access ACI to protect secret attributes (#902481)

[3.0.0-23.el6]
- Installer should not connect to 127.0.0.1. (#895561)
- Don't initialize NSS if we don't have to. (#878220)

[3.0.0-22.el6]
- Set minimum version of bind-dyndb-ldap to 2.3-2 to pick up missing DNS
 zone SOA serial fix (#894131)
- Stopped named service crashed ipa-upgradeconfig program (#895298)
- ipa-replica-prepare crashed when manipulating DNS zone without SOA
 serial (#894143)
- Use new certmonger locking to prevent NSS database corruption during
 CA subsystem renewal (#883484)
- Set minimum selinux-policy to 3.7.19-193 to allow certmonger to talk
 to dbus in an rpm scriptlet. (related #883484)
- Set minimum version of certmonger to 0.61-3 for new locking scheme
 (related #883484)

[3.0.0-21.el6]
- Properly handle migrated uniqueMember attributes (#894090)
- ipa permission-find using valid targetgroup throws internal error (#893827)
- Fix migration of CRLs to new directory location (#893722)
- Installing IPA with a single realm component sometimes fails (#893187)

[3.0.0-20.el6]
- Set maxbersize to a large value to accommodate large CRLs during replica
 installation. (#888956)
- Set minimum version of pki-ca, pki-slient and pki-setup to 9.0.3-29 to
 pick up default CA validity period of 20 years. (#891980)

[3.0.0-19.el6]
- Client installation crashes when Kerberos SRV record is not found (#889583)
- Fix typo in patch 0048 for CVE-2012-5484 (#878220)

[3.0.0-18.el6]
- Cookie Expires date should be locale insensitive to avoid CLI errors (#888915)

[3.0.0-17.el6]
- ipa delegation-find --group option returns internal error (#888524)
- Add missing Requires for python-crypto replacement (#878969)

[3.0.0-16.el6]
- sssd is not enabled on client/server install (#888124)

[3.0.0-15.el6]
- ipa-server-install --uninstall doesn't clear certmonger dirs, which leads
 to install failing (#817080)

[3.0.0-14.el6]
- Compliant client side session cookie behavior. CVE-2012-5631.
 (#886371)

[3.0.0-13.el6]
- Use secure method to retrieve IPA CA during client enrollment.
 CVE-2012-5484 (#878220)
- Reformat patch 0044 so it works with git-am

[3.0.0-12.el6]
- Include /var/lib/sss/pubconf/krb5.include.d/ for domain-realm mappings
 in krb5.conf (#883166)
- Set minimum selinux-policy >= 3.7.19-184 to allow domains that can read
 sssd_public_t files to also list the directory (#881413)
- Remove dist label from changelog entries.
- Fix timestamp on patched files to avoid multilib ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ipa' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~25.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~25.el6", rls:"OracleLinux6"))) {
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
