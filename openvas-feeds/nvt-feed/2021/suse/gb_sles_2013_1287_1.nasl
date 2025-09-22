# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1287.1");
  script_cve_id("CVE-2009-5029", "CVE-2010-4756", "CVE-2011-1089", "CVE-2012-0864", "CVE-2012-3480", "CVE-2013-1914");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1287-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131287-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2013:1287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This collective update for the GNU C library (glibc)
provides the following fixes and enhancements:

Security issues fixed: - Fix stack overflow in getaddrinfo with many results. (bnc#813121, CVE-2013-1914) - Fixed another stack overflow in getaddrinfo with many results
(bnc#828637) - Fix buffer overflow in glob. (bnc#691365)
(CVE-2010-4756) - Fix array overflow in floating point parser [bnc#775690] (CVE-2012-3480) - Fix strtod integer/buffer overflows [bnc#775690] (CVE-2012-3480) -
Make addmntent return errors also for cached streams. [bnc
#676178, CVE-2011-1089] - Fix overflows in vfprintf. [bnc
#770891, CVE 2012-3406] - Add vfprintf-nargs.diff for possible format string overflow. [bnc #747768,
CVE-2012-0864] - Check values from file header in __tzfile_read. [bnc #735850, CVE-2009-5029]

Also several bugs were fixed: - Fix locking in _IO_cleanup.
(bnc#796982) - Fix memory leak in execve. (bnc#805899) -
Fix nscd timestamps in logging (bnc#783196) - Fix perl script error message (bnc#774467) - Fall back to localhost if no nameserver defined (bnc#818630) - Fix incomplete results from nscd. [bnc #753756] - Fix a deadlock in dlsym in case the symbol isn't found, for multithreaded programs. [bnc #760216] - Fix problem with TLS and dlopen.
[#732110] - Backported regex fix for skipping of valid EUC-JP matches [bnc#743689] - Fixed false regex match on incomplete chars in EUC-JP [bnc#743689] - Add glibc-pmap-timeout.diff in order to fix useless connection attempts to NFS servers. [bnc #661460]

Security Issues:

 * CVE-2009-5029
>
 * CVE-2010-4756
>
 * CVE-2011-1089
>
 * CVE-2012-0864
>
 * CVE-2012-3480
>
 * CVE-2013-1914
>");

  script_tag(name:"affected", value:"'glibc' package(s) on SUSE Linux Enterprise Server 10-SP3.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.4~31.77.102.1", rls:"SLES10.0SP3"))) {
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
