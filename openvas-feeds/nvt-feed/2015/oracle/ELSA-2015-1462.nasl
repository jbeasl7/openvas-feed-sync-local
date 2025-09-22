# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123061");
  script_cve_id("CVE-2010-5312", "CVE-2012-6662");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-30 19:03:00 +0000 (Mon, 30 Jan 2023)");

  script_name("Oracle: Security Advisory (ELSA-2015-1462)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1462");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1462.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipa' package(s) announced via the ELSA-2015-1462 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.0.0-47.el6]
- Resolves: #1220788 - Some IPA schema files are not RFC 4512 compliant

[3.0.0-46.el6]
- Use tls version range in NSSHTTPS initialization
- Resolves: #1154687 - POODLE: force using safe ciphers (non-SSLv3) in IPA
 client and server
- Resolves: #1012224 - host certificate not issued to client during
 ipa-client-install

[3.0.0-45.el6]
- Resolves: #1205660 - ipa-client rpm should require keyutils

[3.0.0-44.el6]
- Release 3.0.0-44
- Resolves: #1201454 - ipa breaks sshd config

[3.0.0-43.el6]
- Release 3.0.0-43
- Resolves: #1191040 - ipa-client-automount: failing with error LDAP server
 returned UNWILLING_TO_PERFORM. This likely means that
 minssf is enabled.
- Resolves: #1185207 - ipa-client don't end new line character in
 /etc/nsswitch.conf
- Resolves: #1166241 - CVE-2010-5312 CVE-2012-6662 ipa: various flaws
- Resolves: #1161722 - IDM client registration failure in a high load
 environment
- Resolves: #1154687 - POODLE: force using safe ciphers (non-SSLv3) in IPA
 client and server
- Resolves: #1146870 - ipa-client-install fails with 'KerbTransport instance
 has no attribute '__conn'' traceback
- Resolves: #1132261 - ipa-client-install failing produces a traceback
 instead of useful error message
- Resolves: #1131571 - Do not allow IdM server/replica/client installation
 in a FIPS-140 mode
- Resolves: #1198160 - /usr/sbin/ipa-server-install --uninstall does not
 clean /var/lib/ipa/pki-ca
- Resolves: #1198339 - ipa-client-install adds extra sss to sudoers in
 nsswitch.conf
- Require: 389-ds-base >= 1.2.11.15-51
- Require: mod_nss >= 1.0.10
- Require: pki-ca >= 9.0.3-40
- Require: python-nss >= 0.16");

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

  if(!isnull(res = isrpmvuln(pkg:"ipa", rpm:"ipa~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~3.0.0~47.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ipa-server-trust-ad", rpm:"ipa-server-trust-ad~3.0.0~47.el6", rls:"OracleLinux6"))) {
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
