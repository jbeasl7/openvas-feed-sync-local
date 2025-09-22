# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123764");
  script_cve_id("CVE-2012-2697");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:13 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0132)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0132");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0132.html");
  script_xref(name:"URL", value:"http://www.mail-archive.com/autofs@linux.kernel.org/msg07910.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs' package(s) announced via the ELSA-2013-0132 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[5.0.1-0.rc2.177.0.1.el5]
- apply fix from NetApp to use tcp before udp
 [link moved to references]
 (Bert Barbe) [orabug 6827898]

[5.0.1-0.rc2.177.el5]
- bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
 - disable hosts map HUP signal update.
- Related: rhbz#714766

[5.0.1-0.rc2.176.el5]
- bz859890 - no --timeout option usage demonstrated in auto.master FORMAT
 options man page section
 - add timeout option description to man page.
- Resolves: rhbz#859890

[5.0.1-0.rc2.175.el5]
- bz845503 - autofs initscript problems
 - fix status() return code now gets lost due to adding lock file check.
- Related: rhbz#845503

[5.0.1-0.rc2.174.el5]
- bz585058 - autofs5 init script times out before automount exits and
 incorrectly shows that autofs5 stop failed
 - fix don't wait forever for shutdown.
- bz845503 - autofs initscript problems
 - don't unconditionally call stop on restart.
 - fix usage message.
 - fix status return code when daemon is dead but lock file exists.
- Related: rhbz#585058 rhbz#845503

[5.0.1-0.rc2.173.el5]
- bz845503 - autofs initscript problems
 - don't use status() function in restart, it can't be relied upon.
- Related: rhbz#845503

[5.0.1-0.rc2.172.el5]
- bz845503 - autofs initscript problems
 - fix status call in restart must specify pid file name.
- Related: rhbz#845503

[5.0.1-0.rc2.171.el5]
- bz845503 - autofs initscript problems
 - make redhat init script more lsb compliant.
- Resolves: rhbz#845503

[5.0.1-0.rc2.170.el5]
- bz847101 - System unresponsiveness and CPU starvation when launching source code script
 - check negative cache much earlier.
 - don't use pthread_rwlock_tryrdlock().
 - remove state machine timed wait.
- Related: rhbz#847101

[5.0.1-0.rc2.169.el5]
- bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
 - fix offset dir removal.
- Related: rhbz#714766

[5.0.1-0.rc2.168.el5]
- bz585058 - autofs5 init script times out before automount exits and
 incorrectly shows that autofs5 stop failed
 - make autofs wait longer for shutdown.
- Resolves: rhbz#585058

[5.0.1-0.rc2.167.el5]
- bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
 - fix expire race.
 - fix remount deadlock.
 - fix umount recovery of busy direct mount.
 - fix offset mount point directory removal.
 - remove move mount code.
 - fix remount of multi mount.
 - fix device ioctl alloc path check.
 - refactor hosts lookup module.
 - remove cache update from parse_mount().
 - add function to delete offset cache entry.
 - allow update of multi mount offset entries.
 - add hup signal handling to hosts map.
- Resolves: rhbz#714766

[5.0.1-0.rc2.166.el5]
- bz826633 - autofs crashes on lookup of a key containing a backslash
 - fix fix LDAP result leaks on error paths.
 - fix result null check in read_one_map().
- Resolves: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'autofs' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.1~0.rc2.177.0.1.el5", rls:"OracleLinux5"))) {
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
