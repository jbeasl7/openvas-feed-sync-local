# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122756");
  script_cve_id("CVE-2015-3455");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:29 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-2378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2378");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2378.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the ELSA-2015-2378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7:3.3.8-26]
- Related: #1186768 - removing patch, because of missing tests and
 incorrect patch

[7:3.3.8-25]
- Related: #1102842 - squid rpm package misses /var/run/squid needed for
 smp mode. Squid needs write access to /var/run/squid.

[7:3.3.8-24]
- Related: #1102842 - squid rpm package misses /var/run/squid needed for
 smp mode. Creation of /var/run/squid was also needed to be in SPEC file.

[7:3.3.8-23]
- Related: #1102842 - squid rpm package misses /var/run/squid needed for
 smp mode. Creation of this directory was moved to tmpfiles.d conf file.

[7:3.3.8-22]
- Related: #1102842 - squid rpm package misses /var/run/squid needed for
 smp mode. Creation of this directory was moved to service file.

[7:3.3.8-21]
- Resolves: #1263338 - squid with digest auth on big endian systems
 start looping

[7:3.3.8-20]
- Resolves: #1186768 - security issue: Nonce replay vulnerability
 in Digest authentication

[7:3.3.8-19]
- Resolves: #1225640 - squid crashes by segfault when it reboots

[7:3.3.8-18]
- Resolves: #1102842 - squid rpm package misses /var/run/squid needed for
 smp mode

[7:3.3.8-17]
- Resolves: #1233265 - CVE-2015-3455 squid: incorrect X509 server
 certificate validation

[7:3.3.8-16]
- Resolves: #1080042 - Supply a firewalld service file with squid

[7:3.3.8-15]
- Resolves: #1161600 - Squid does not serve cached responses
 with Vary headers

[7:3.3.8-14]
- Resolves: #1198778 - Filedescriptor leaks on snmp

[7:3.3.8-13]
- Resolves: #1204375 - squid sends incorrect ssl chain breaking newer gnutls
 using applications");

  script_tag(name:"affected", value:"'squid' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.3.8~26.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-sysvinit", rpm:"squid-sysvinit~3.3.8~26.el7", rls:"OracleLinux7"))) {
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
