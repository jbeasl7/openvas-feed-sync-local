# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123168");
  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:14 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 19:03:00 +0000 (Mon, 30 Jan 2023)");

  script_name("Oracle: Security Advisory (ELSA-2015-0442)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0442");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0442.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa' package(s) announced via the ELSA-2015-0442 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.1.0-18.0.1]
- Replace login-screen-logo.png [20362818]
- Drop subscription-manager requires for OL7
- Drop redhat-access-plugin-ipa requires for OL7
- Blank out header-logo.png product-name.png

[4.1.0-18]
- Fix ipa-pwd-extop global configuration caching (#1187342)
- group-detach does not add correct objectclasses (#1187540)

[4.1.0-17]
- Wrong directories created on full restore (#1186398)
- ipa-restore crashes if replica is unreachable (#1186396)
- idoverrideuser-add option --sshpubkey does not work (#1185410)

[4.1.0-16]
- PassSync does not sync passwords due to missing ACIs (#1181093)
- ipa-replica-manage list does not list synced domain (#1181010)
- Do not assume certmonger is running in httpinstance (#1181767)
- ipa-replica-manage disconnect fails without password (#1183279)
- Put LDIF files to their original location in ipa-restore (#1175277)
- DUA profile not available anonymously (#1184149)
- IPA replica missing data after master upgraded (#1176995)

[4.1.0-15]
- Re-add accidentally removed patches for #1170695 and #1164896

[4.1.0-14]
- IPA Replicate creation fails with error 'Update failed! Status: [10 Total
 update abortedLDAP error: Referral]' (#1166265)
- running ipa-server-install --setup-dns results in a crash (#1072502)
- DNS zones are not migrated into forward zones if 4.0+ replica is added
 (#1175384)
- gid is overridden by uid in default trust view (#1168904)
- When migrating warn user if compat is enabled (#1177133)
- Clean up debug log for trust-add (#1168376)
- No error message thrown on restore(full kind) on replica from full backup
 taken on master (#1175287)
- ipa-restore proceed even IPA not configured (#1175326)
- Data replication not working as expected after data restore from full backup
 (#1175277)
- IPA externally signed CA cert expiration warning missing from log (#1178128)
- ipa-upgradeconfig fails in CA-less installs (#1181767)
- IPA certs fail to autorenew simultaneously (#1173207)
- More validation required on ipa-restore's options (#1176034)

[4.1.0-13]
- Expand the token auth/sync windows (#919228)
- Access is not rejected for disabled domain (#1172598)
- krb5kdc crash in ldap_pvt_search (#1170695)
- RHEL7.1 IPA server httpd avc denials after upgrade (#1164896)

[4.1.0-12]
- RHEL7.1 ipa-cacert-manage renewed certificate from MS ADCS not compatible
 (#1169591)
- CLI doesn't show SSHFP records with SHA256 added via nsupdate (regression)
 (#1172578)

[4.1.0-11]
- Throw zonemgr error message before installation proceeds (#1163849)
- Winsync: Setup is broken due to incorrect import of certificate (#1169867)
- Enable last token deletion when password auth type is configured (#919228)
- ipa-otp-lasttoken loads all user's tokens on every mod/del (#1166641)
- add --hosts and --hostgroup options to allow/retrieve keytab methods
 (#1007367)
- Extend host-show to add the view attribute in set of default attributes
 (#1168916)
- Prefer TCP ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ipa' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~4.1.0~18.0.1.el7", rls:"OracleLinux7"))) {
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
