# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122117");
  script_cve_id("CVE-2010-4341");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:22 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0975)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0975");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0975.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd' package(s) announced via the ELSA-2011-0975 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.5.1-37]
- Reverts: rhbz#680443 - Dynamic DNS update fails if multiple servers are
- given in ipa_server config option

[1.5.1-36]
- Resolves: rhbz#709333 - sssd. should require sssd-client.

[1.5.1-35]
- Resolves: rhbz#707340 - latest sssd fails if ldap_default_authtok_type is
- not mentioned
- Resolves: rhbz#707574 - SSSD's async resolver only tries the first
- nameserver in /etc/resolv.conf

[1.5.1-34]
- Resolves: rhbz#701702 - sssd client libraries use select() but should use
- poll() instead

[1.5.1-33]
- Related: rhbz#700858 - Automatic TGT renewal overwrites cached password
- Fix segfault in TGT renewal

[1.5.1-32]
- Resolves: rhbz#700858 - Automatic TGT renewal overwrites cached password

[1.5.1-30]
- Resolves: rhbz#696979 - Filters not honoured against fully-qualified users

[1.5.1-29]
- Resolves: rhbz#694149 - SSSD consumes GBs of RAM, possible memory leak

[1.5.1-28]
- Related: rhbz#691900 - SSSD needs to fall back to 'cn' for GECOS
- information

[1.5.1-27]
- Related: rhbz#694853 - SSSD crashes during getent when anonymous bind is
- disabled

[1.5.1-26]
- Resolves: rhbz#695476 - Unable to resolve SRV record when called with
[in ldap_uri]
- Related: rhbz#694853 - SSSD crashes during getent when anonymous bind is
- disabled

[1.5.1-25]
- Resolves: rhbz#694853 - SSSD crashes during getent when anonymous bind is
- disabled

[1.5.1-24]
- Resolves: rhbz#692960 - Process /usr/libexec/sssd/sssd_be was killed by
- signal 11 (SIGSEGV)
- Fix is to not attempt to resolve nameless servers

[1.5.1-23]
- Resolves: rhbz#691900 - SSSD needs to fall back to 'cn' for GECOS
- information

[1.5.1-21]
- Resolves: rhbz#690867 - Groups with a zero-length memberuid attribute can
- cause SSSD to stop caching and responding to
- requests

[1.5.1-20]
- Resolves: rhbz#690287 - Traceback messages seen while interrupting
- sss_obfuscate using ctrl+d
- Resolves: rhbz#690814 - [abrt] sssd-1.2.1-28.el6_0.4: _talloc_free: Process
- /usr/libexec/sssd/sssd_be was killed by signal 11
- (SIGSEGV)

[1.5.1-19]
- Related: rhbz#690096 - SSSD should skip over groups with multiple names

[1.5.1-18]
- Resolves: rhbz#690093 - SSSD breaks on RDNs with a comma in them
- Resolves: rhbz#690096 - SSSD should skip over groups with multiple names
- Resolves: rhbz#689887 - group memberships are not populated correctly during
- IPA provider initgroups
- Resolves: rhbz#688697 - Skip users and groups that have incomplete contents
- Resolves: rhbz#688694 - authconfig fails when access_provider is set as krb5
- in sssd.conf

[1.5.1-17]
- Resolves: rhbz#688677 - Build SSSD in RHEL 5.7 against openldap24-libs
- Adds support for following LDAP referrals and using Mozilla NSS for crypto
- support

[1.5.1-16]
- Resolves: rhbz#683260 - sudo/ldap lookup via sssd gets stuck for 5min
- waiting on netgroup
- Resolves: rhbz#683585 - sssd consumes 100% CPU
- Related: rhbz#680441 - sssd does not handle kerberos server IP ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'sssd' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.5.1~37.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.5.1~37.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.5.1~37.el5", rls:"OracleLinux5"))) {
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
