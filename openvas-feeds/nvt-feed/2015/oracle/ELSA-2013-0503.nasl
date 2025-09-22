# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123707");
  script_cve_id("CVE-2012-4450");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:29 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0503");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0503.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2013-0503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.11.15-11]
- Resolves: Bug 896256 - updating package touches configuration files

[1.2.11.15-10]
- Resolves: Bug 889083 - For modifiersName/internalModifiersName feature, internalModifiersname is not working for DNA plugin

[1.2.11.15-9]
- Resolves: Bug 891930 - DNA plugin no longer reports additional info when range is depleted

[1.2.11.15-8]
- Resolves: Bug 887855 - RootDN Access Control plugin is missing after upgrade from RHEL63 to RHEL64

[1.2.11.15-7]
- Resolves: Bug 830355 - [RFE] improve cleanruv functionality
- Resolves: Bug 876650 - Coverity revealed defects
- Ticket #20 - [RFE] Allow automember to work on entries that have already been added (Bug 768084)
- Resolves: Bug 834074 - [RFE] Disable replication agreements
- Resolves: Bug 878111 - ns-slapd segfaults if it cannot rename the logs

[1.2.11.15-6]
- Resolves: Bug 880305 - spec file missing dependencies for x86_64 6ComputeNode
- use perl-Socket6 on RHEL6

[1.2.11.15-5]
- Resolves: Bug 880305 - spec file missing dependencies for x86_64 6ComputeNode

[1.2.11.15-4]
- Resolves: Bug 868841 - Newly created users with organizationalPerson objectClass fails to sync from AD to DS with missing attribute error
- Resolves: Bug 868853 - Winsync: DS error logs report wrong version of Windows AD when winsync is configured.
- Resolves: Bug 875862 - crash in DNA if no dnamagicregen is specified
- Resolves: Bug 876694 - RedHat Directory Server crashes (segfaults) when moving ldap entry
- Resolves: Bug 876727 - Search with a complex filter including range search is slow
- Ticket #495 - internalModifiersname not updated by DNA plugin (Bug 834053)

[1.2.11.15-3]
- Resolves: Bug 870158 - slapd entered to infinite loop during new index addition
- Resolves: Bug 870162 - Cannot abandon simple paged result search
- c970af0 Coverity defects
- 1ac087a Fixing compiler warnings in the posix-winsync plugin
- 2f960e4 Coverity defects
- Ticket #491 - multimaster_extop_cleanruv returns wrong error codes

[1.2.11.15-2]
- Resolves: Bug 834063 [RFE] enable attribute that tracks when a password was last set on an entry in the LDAP store, Ticket #478 passwordTrackUpdateTime stops working with subtree password policies
- Resolves: Bug 847868 [RFE] support posix schema for user and group sync, Ticket #481 expand nested posix groups
- Resolves: Bug 860772 Change on SLAPI_MODRDN_NEWSUPERIOR is not evaluated in acl
- Resolves: Bug 863576 Dirsrv deadlock locking up IPA
- Resolves: Bug 864594 anonymous limits are being applied to directory manager

[1.2.11.15-1]
- Resolves: Bug 856657 dirsrv init script returns 0 even when few or all instances fail to start
- Resolves: Bug 858580 389 prevents from adding a posixaccount with userpassword after schema reload

[1.2.11.14-1]
- Resolves: Bug 852202 Ipa master system initiated more than a dozen simultaneous replication sessions, shut itself down and wiped out its db
- Resolves: Bug 855438 CLEANALLRUV ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~11.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~11.el6", rls:"OracleLinux6"))) {
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
