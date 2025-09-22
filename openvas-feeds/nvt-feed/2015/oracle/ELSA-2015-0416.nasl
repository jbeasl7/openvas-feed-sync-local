# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123173");
  script_cve_id("CVE-2014-8105", "CVE-2014-8112");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:18 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-0416)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0416");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0416.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2015-0416 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.3.3.1-13]
- release 1.3.3.1-13
- Resolves: bug 1183655 - Fixed Covscan FORWARD_NULL defects (DS 47988)

[1.3.3.1-12]
- release 1.3.3.1-12
- Resolves: bug 1182477 - Windows Sync accidentally cleared raw_entry (DS 47989)
- Resolves: bug 1180325 - upgrade script fails if /etc and /var are on different file systems (DS 47991 )
- Resolves: bug 1183655 - Schema learning mechanism, in replication, unable to extend an existing definition (DS 47988)

[1.3.3.1-11]
- release 1.3.3.1-11
- Resolves: bug 1080186 - During delete operation do not refresh cache entry if it is a tombstone (DS 47750)

[1.3.3.1-10]
- release 1.3.3.1-10
- Resolves: bug 1172731 - CVE-2014-8112 password hashing bypassed when 'nsslapd-unhashed-pw-switch' is set to off
- Resolves: bug 1166265 - DS hangs during online total update (DS 47942)
- Resolves: bug 1168151 - CVE-2014-8105 information disclosure through 'cn=changelog' subtree
- Resolves: bug 1044170 - Allow memberOf suffixes to be configurable (DS 47526)
- Resolves: bug 1171356 - Bind DN tracking unable to write to internalModifiersName without special permissions (DS 47950)
- Resolves: bug 1153737 - logconv.pl -- support parsing/showing/reporting different protocol versions (DS 47949)
- Resolves: bug 1171355 - start dirsrv after chrony on RHEL7 and Fedora (DS 47947)
- Resolves: bug 1170707 - cos_cache_build_definition_list does not stop during server shutdown (DS 47967)
- Resolves: bug 1170708 - COS memory leak when rebuilding the cache (DS - Ticket 47969)
- Resolves: bug 1170709 - Account lockout attributes incorrectly updated after failed SASL Bind (DS 47970)
- Resolves: bug 1166260 - cookie_change_info returns random negative number if there was no change in a tree (DS 47960)
- Resolves: bug 1012991 - Error log levels not displayed correctly (DS 47636)
- Resolves: bug 1108881 - rsearch filter error on any search filter (DS 47722)
- Resolves: bug 994690 - Allow dynamically adding/enabling/disabling/removing plugins without requiring a server restart (DS 47451)
- Resolves: bug 1162997 - Running a plugin task can crash the server (DS 47451)
- Resolves: bug 1166252 - RHEL7.1 ns-slapd segfault when ipa-replica-install restarts (DS 47451)
- Resolves: bug 1172597 - Crash if setting invalid plugin config area for MemberOf Plugin (DS 47525)
- Resolves: bug 1139882 - coverity defects found in 1.3.3.x (DS 47965)

[1.3.3.1-9]
- release 1.3.3.1-9
- Resolves: bug 1153737 - Disable SSL v3, by default. (DS 47928)
- Resolves: bug 1163461 - Should not check aci syntax when deleting an aci (DS 47953)

[1.3.3.1-8]
- release 1.3.3.1-8
- Resolves: bug 1156607 - Crash in entry_add_present_values_wsi_multi_valued (DS 47937)
- Resolves: bug 1153737 - Disable SSL v3, by default (DS 47928, DS 47945, DS 47948)
- Resolves: bug 1158804 - Malformed cookie for LDAP Sync makes DS crash (DS 47939)

[1.3.3.1-7]
- release 1.3.3.1-7
- Resolves: bug 1153737 - Disable SSL v3, by default ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.3.1~13.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.3.1~13.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.3.1~13.el7", rls:"OracleLinux7"))) {
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
