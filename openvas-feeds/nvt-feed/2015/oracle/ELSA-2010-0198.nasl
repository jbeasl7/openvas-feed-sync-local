# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122377");
  script_cve_id("CVE-2009-3767");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:46 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2010-0198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0198");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0198.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap' package(s) announced via the ELSA-2010-0198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.3.43-12]
- updated spec file, so the compat-libs linking patch applies
 correctly

[2.3.43-11]
- backported patch to handle null character in TLS
 certificates (#560912)

[2.3.43-10]
- updated chase-referral patch to compile cleanly
- updated init script (#562714)

[2.3.43-9]
- updated ldap.sysconf to include SLAPD_LDAP, SLAPD_LDAPS and
 SLAPD_LDAPI options (#559520)

[2.3.43-8]
- fixed connection freeze when TLSVerifyClient = allow (#509230)

[2.3.43-7]
- fixed chasing referrals in libldap (#510522)

[2.3.43-6]
- fixed possible double free() in rwm overlay (#495628)
- updated slapd man page and slapcat usage string (#468206)
- updated default config for slapd - deleted syncprov module (#466937)
- fixed migration tools autofs generated format (#460331)
- fixed migration tools numbers detection in /etc/shadow (#113857)
- fixed migration tools base ldif (#104585)

[2.3.43-5]
- implementation of limit adjustment before starting slapd (#527313)
- init script no longer executes script in /tmp (#483356)
- slapd not starting with ldap:/// every time (#481003)
- delay between TERM and KILL when shutting down slapd (#452064)

[2.3.43-4]
- fixed compat libs linking (#503734)
- activated lightweight dispatcher feature (#507276)
- detection of timeout after failed result (#495701");

  script_tag(name:"affected", value:"'openldap' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.43_2.2.29~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.43~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.43~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.43~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.43~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-overlays", rpm:"openldap-servers-overlays~2.3.43~12.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.43~12.el5", rls:"OracleLinux5"))) {
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
