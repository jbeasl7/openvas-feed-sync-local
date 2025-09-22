# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123164");
  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345", "CVE-2014-5352", "CVE-2014-5353", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-0439)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0439");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2015-0439 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.12.2-14]
- fix for kinit -C loops (#1184629, MIT/krb5 issue 243, 'Do not
 loop on principal unknown errors').

[1.12.2-13]
- fix for CVE-2014-5352 (#1179856) 'gss_process_context_token()
 incorrectly frees context (MITKRB5-SA-2015-001)'
- fix for CVE-2014-9421 (#1179857) 'kadmind doubly frees partial
 deserialization results (MITKRB5-SA-2015-001)'
- fix for CVE-2014-9422 (#1179861) 'kadmind incorrectly
 validates server principal name (MITKRB5-SA-2015-001)'
- fix for CVE-2014-9423 (#1179863) 'libgssrpc server applications
 leak uninitialized bytes (MITKRB5-SA-2015-001)'

[1.12.2-12]
- fix for CVE-2014-5354 (#1174546) 'krb5: NULL pointer
 dereference when using keyless entries'

[1.12.2-11]
- fix for CVE-2014-5353 (#1174543) 'Fix LDAP misused policy
 name crash'

[1.12.2-10]
- In ksu, without the -e flag, also check .k5users (#1105489)
 When ksu was explicitly told to spawn a shell, a line in .k5users which
 listed '*' as the allowed command would cause the principal named on the
 line to be considered as a candidate for authentication.
 When ksu was not passed a command to run, which implicitly meant that
 the invoking user wanted to run the target user's login shell, knowledge
 that the principal was a valid candidate was ignored, which could cause
 a less optimal choice of the default target principal.
 This doesn't impact the authorization checks which we perform later.
 Patch by Nalin Dahyabhai [1.12.2-9]- Undo libkadmclnt SONAME change (from 8 to 9) which originally happened in the krb5 1.12 rebase (#1166012) but broke rubygem-rkerberos (sort of ruby language bindings for libkadmclnt&co.) dependencies, as side effect of rubygem-rkerberos using private interfaces in libkadmclnt.[1.12.2-8]- fix the problem where the %license file has been a dangling symlink- ksu: pull in fix from pull #206 to avoid breakage when the default_ccache_name doesn't include a cache type as a prefix- ksu: pull in a proposed fix for pull #207 to avoid breakage when the invoking user doesn't already have a ccache[1.12.2-7]- pull in patch from master to load plugins with RTLD_NODELETE, when defined (RT#7947)[1.12.2-6]- backport patch to make the client skip checking the server's reply address when processing responses to password-change requests, which between NAT and upcoming HTTPS support, can cause us to erroneously report an error to the user when the server actually reported success (RT#7886)- backport support for accessing KDCs and kpasswd services via HTTPS proxies (marked by being specified as https URIs instead as hostnames or hostname-and-port), such as the one implemented in python-kdcproxy (RT#7929, #109919), and pick up a subsequent patch to build HTTPS as a plugin[1.12.2-5]- backport fix for trying all compatible keys when not being strict about acceptor names while reading AP-REQs (RT#7883, #1078888)- define _GNU_SOURCE in files where we use EAI_NODATA, to make sure that it's ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit", rpm:"krb5-pkinit~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.12.2~14.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.12.2~14.el7", rls:"OracleLinux7"))) {
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
