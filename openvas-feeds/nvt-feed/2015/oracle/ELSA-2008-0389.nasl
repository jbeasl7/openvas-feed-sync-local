# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122584");
  script_cve_id("CVE-2007-5794");
  script_tag(name:"creation_date", value:"2015-10-08 11:48:38 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2008-0389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0389");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0389.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss_ldap' package(s) announced via the ELSA-2008-0389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[253-12]
- rebuild

[253-11]
- backport changes to group parsing from version 254 to fix heap corruption
 when parsing nested groups (#444031)

[253-10]
- remove unnecessary nss_ldap linkage to libnsl (part of #427370)

[253-9]
- rebuild

[253-8]
- incorporate Tomas Janouseks fix to prevent re-use of connections across
 fork() (#252337)

[253-7]
- add keyutils-libs-devel and libselinux-devel as a buildrequires: in order to
 static link with newer Kerberos (#427370)

[253-6]
- suppress password-expired errors encountered during referral chases during
 modify requests (#335661)
- interpret server-supplied policy controls when chasing referrals, so that
 we don't give up when following a referral for a password change after
 reset (#335661)
- don't attempt to change the password using ldap_modify if the password
 change mode is 'exop_send_old' (we already didn't for 'exop') (#364501)
- don't drop the supplied password if the directory server indicates that
 the password needs to be changed because its just been reset: we may need
 it to chase a referral later (#335661)
- correctly detect libresolv and build a URI using discovered settings, so that
 server discovery can work again (#254172)
- honor the 'port' setting again by correctly detecting when a URI doesn't
 already specify one (#326351)");

  script_tag(name:"affected", value:"'nss_ldap' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"nss_ldap", rpm:"nss_ldap~253~12.el5", rls:"OracleLinux5"))) {
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
