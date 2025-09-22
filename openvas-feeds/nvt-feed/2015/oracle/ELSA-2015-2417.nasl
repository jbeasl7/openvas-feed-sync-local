# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122743");
  script_cve_id("CVE-2014-8169");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:20 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-2417)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2417");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2417.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs' package(s) announced via the ELSA-2015-2417 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.7-54.0.1]
- add autofs-5.0.5-lookup-mounts.patch [Orabug:12658280] (Bert Barbe)

[1:5.0.7-54]
- bz1263508 - Heavy program map usage can lead to a hang
 - fix out of order call in program map lookup.
- Resolves: rhbz#1263508

[1:5.0.7-53]
- bz1238573 - RFE: autofs MAP_HASH_TABLE_SIZE description
 - update map_hash_table_size description.
- Resolves: rhbz#1238573

[1:5.0.7-52]
- bz1233069 - Direct map does not expire if map is initially empty
 - update patch to fix expiry problem.
- Related: rhbz#1233069

[1:5.0.7-51]
- bz1233065 - 'service autofs reload' does not reloads new mounts only
 when 'sss' or 'ldap' is used in '/etc/nsswitch.conf' file
 - init qdn before use in get_query_dn().
 - fix left mount count return from umount_multi_triggers().
 - fix return handling in sss lookup module.
 - move query dn calculation from do_bind() to do_connect().
 - make do_connect() return a status.
 - make connect_to_server() return a status.
 - make find_dc_server() return a status.
 - make find_server() return a status.
 - fix return handling of do_reconnect() in ldap module.
- bz1233067 - autofs is performing excessive direct mount map re-reads
 - fix direct mount stale instance flag reset.
- bz1233069 - Direct map does not expire if map is initially empty
 - fix direct map expire not set for initial empty map.
- Resolves: rhbz#1233065 rhbz#1233067 rhbz#1233069

[1:5.0.7-50]
- bz1218045 - Similar but unrelated NFS exports block proper mounting of
 'parent' mount point
 - remove unused offset handling code.
 - fix mount as you go offset selection.
- Resolves: rhbz#1218045

[1:5.0.7-49]
- bz1166457 - Autofs unable to mount indirect after attempt to mount wildcard
 - make negative cache update consistent for all lookup modules.
 - ensure negative cache isn't updated on remount.
 - don't add wildcard to negative cache.
- bz1162041 - priv escalation via interpreter load path for program based
 automount maps
 - add a prefix to program map stdvars.
 - add config option to force use of program map stdvars.
- bz1161474 - automount segment fault in parse_sun.so for negative parser tests
 - fix incorrect check in parse_mount().
- bz1205600 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate
 exports in the NFS server
 - handle duplicates in multi mounts.
- bz1201582 - autofs: MAPFMT_DEFAULT is not macro in lookup_program.c
 - fix macro usage in lookup_program.c.
- Resolves: rhbz#1166457 rhbz#1162041 rhbz#1161474 rhbz#1205600 rhbz#1201582");

  script_tag(name:"affected", value:"'autofs' package(s) on Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.7~54.0.1.el7", rls:"OracleLinux7"))) {
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
