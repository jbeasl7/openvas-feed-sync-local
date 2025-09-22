# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123055");
  script_cve_id("CVE-2014-8169");
  script_tag(name:"creation_date", value:"2015-10-06 10:58:46 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2015-1344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1344");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1344.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs' package(s) announced via the ELSA-2015-1344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.5-113.0.1]
- add autofs-5.0.5-lookup-mounts.patch [Orabug:12658280] (Bert Barbe)
 use tcp instead of udp

[5.0.5-113]
- bz1201195 - autofs: MAPFMT_DEFAULT is not macro in lookup_program.c
 - fix macro usage in lookup_program.c.
- Resolves: rhbz#1201195

[5.0.5-112]
- bz1124083 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate
 exports in the NFS server
 - fix use after free in patch to handle duplicate in multi mounts.
 - change log messages to try and make them more sensible.
- fix log entry for rev 5.0.5-111 below.
- Related: rhbz#1124083

[5.0.5-111]
- bz1153130 - autofs-5.0.5-109 with upgrade to RHEL 6.6 no longer recognizes
 +yp: in auto.master
 - fix fix master map type check.
- bz1156387 - autofs /net maps do not refresh list of shares exported on the
 NFS server
 - fix typo in update_hosts_mounts().
 - fix hosts map update on reload.
- bz1160446 - priv escalation via interpreter load path for program based
 automount maps
 - add a prefix to program map stdvars.
 - add config option to force use of program map stdvars.
- bz1175671 - automount segment fault in parse_sun.so for negative parser tests
 - fix incorrect check in parse_mount().
- bz1124083 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate
 exports in the NFS server
 - fix fix map entry duplicate offset detection (dependednt patch).
 - handle duplicates in multi mounts.
- Resolves: rhbz#1153130 rhbz#1156387 rhbz#1160446 rhbz#1175671 rhbz#1124083

[5.0.5-110]
- bz1163957 - Autofs unable to mount indirect after attempt to mount wildcard
 - make negative cache update consistent for all lookup modules.
 - ensure negative cache isn't updated on remount.
 - don't add wildcard to negative cache.
- Resolves: rhbz#1163957");

  script_tag(name:"affected", value:"'autofs' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.5~113.0.1.el6", rls:"OracleLinux6"))) {
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
