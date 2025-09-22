# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123891");
  script_cve_id("CVE-2012-1164");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:55 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0899)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0899");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0899.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap' package(s) announced via the ELSA-2012-0899 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.4.23-26]
- fix: MozNSS CA cert dir does not work together with PEM CA cert file (#818844)
- fix: memory leak: def_urlpre is not freed (#816168)
- fix update: Default SSL certificate bundle is not found by openldap library (#742023)

[2.4.23-25]
- fix update: Default SSL certificate bundle is not found by openldap library (#742023)

[2.4.23-24]
- fix update: Default SSL certificate bundle is not found by openldap library (#742023)
- fix: memberof overlay on the frontend database causes server segfault (#730745)

[2.4.23-23]
- security fix: CVE-2012-1164: assertion failure by processing search queries
 requesting only attributes for particular entry (#813162)

[2.4.23-22]
- fix: libraries leak memory when following referrals (#807363)

[2.4.23-21]
- fix: ldapsearch crashes with invalid parameters (#743781)
- fix: replication (syncrepl) with TLS causes segfault (#783445)
- fix: openldap server in MirrorMode sometimes fails to resync via syncrepl (#784211)
- use portreserve to reserve LDAPS port (636/tcp+udp) (#790687)
- fix: missing options in manual pages of client tools (#745470)
- fix: SASL_NOCANON option missing in ldap.conf manual page (#732916)
- fix: slapd segfaults when certificate key cannot be loaded (#796808)
- Jan Synacek + fix: overlay constraint with count option work bad with modify operation (#742163) + fix: Default SSL certificate bundle is not found by openldap library (#742023) + fix: Duplicate close() calls in OpenLDAP (#784203)");

  script_tag(name:"affected", value:"'openldap' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.23~26.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.23~26.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.23~26.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.23~26.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.4.23~26.el6", rls:"OracleLinux6"))) {
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
