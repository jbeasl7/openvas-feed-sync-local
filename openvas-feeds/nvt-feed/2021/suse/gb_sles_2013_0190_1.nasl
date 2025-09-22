# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0190.1");
  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421", "CVE-2012-5530");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0190-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130190-1/");
  script_xref(name:"URL", value:"http://www.raspberrypi.org/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcp' package(s) announced via the SUSE-SU-2013:0190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"pcp was updated to version 3.6.10 which fixes security issues and also brings a lot of new features.

 *

 Update to pcp-3.6.10.

 o Transition daemons to run under an unprivileged account. o Fixes for security advisory CVE-2012-5530:
tmpfile flaws, (bnc#782967). o Fix pcp(1) command short-form pmlogger reporting. o Fix pmdalogger error handling for directory files. o Fix pmstat handling of odd corner case in CPU metrics. o Correct the python ctype used for pmAtomValue 32bit ints. o Add missing RPM spec dependency for python-ctypes. o Corrections to pmdamysql metrics units. o Add pmdamysql slave status metrics. o Improve pmcollectl error messages. o Parameterize pmcollectl CPU counts in interrupt subsys. o Fix generic RPM packaging for powerpc builds. o Fix python API use of reentrant libpcp string routines. o Python code backporting for RHEL5 in qa and pmcollectl. o Fix edge cases in capturing interrupt error counts.
 *

 Update to pcp-3.6.9.

 o Python wrapper for the pmimport API o Make sar2pcp work with the sysstat versions from RHEL5, RHEL6,
and all recent Fedora versions (which is almost all current versions of sysstat verified). o Added a number of additional metrics into the importer for people starting to use it to analyse sar data from real customer incidents. o Rework use of C99 'restrict' keyword in pmdalogger (Debian bug: 689552) o Alot of work on the PCP QA suite, special thanks to Tomas Dohnalek for all his efforts there. o Win32 build updates o Add 'raw' disk active metrics so that existing tools like iostat can be emulated o Allow sar2pcp to accept XML input directly (.xml suffix), allowing it to not have to run on the same platform as the sadc/sadf that originally generated it. o Add PMI error codes into the PCP::LogImport perl module. o Fix a typo in pmiUnits man page synopsis section o Resolve pmdalinux ordering issue in NUMA/CPU indom setup (Redhat bug: 858384) o Remove unused pmcollectl imports (Redhat bug: 863210) o Allow event traces to be used in libpcp interpolate mode
 *

 Update to pcp-3.6.8.

 o Corrects the disk/partition identification for the MMC driver, which makes disk indom handling correct on the Raspberry Pi ([link moved to references]) o Several minor/basic fixes for pmdaoracle. o Improve pmcollectl compatibility. o Make a few clarifications to pmcollectl.1.
o Improve python API test coverage. o Numerous updates to the test suite in general. o Allow pmda Install scripts to specify own dso name again. o Reconcile spec file differences between PCP flavours. o Fix handling of multiple contexts with a remote namespace. o Core socket interface abstractions to support NSS (later). o Fix man page SYNOPSIS section for pmUnpackEventRecords. o Add
--disable-shared build option for static builds.
 *

 Update to pcp-3.6.6.

 o Added the python PMAPI bindings and an initial python client in pmcollectl. Separate, new package exists for python ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pcp' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libpcp3", rpm:"libpcp3~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp", rpm:"pcp~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-iostat2pcp", rpm:"pcp-import-iostat2pcp~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-mrtg2pcp", rpm:"pcp-import-mrtg2pcp~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-sar2pcp", rpm:"pcp-import-sar2pcp~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcp-import-sheet2pcp", rpm:"pcp-import-sheet2pcp~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogImport", rpm:"perl-PCP-LogImport~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-LogSummary", rpm:"perl-PCP-LogSummary~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-MMV", rpm:"perl-PCP-MMV~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PCP-PMDA", rpm:"perl-PCP-PMDA~3.6.10~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2013.1.7~0.5.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"permissions", rpm:"permissions~2013.1.7~0.3.1", rls:"SLES11.0SP2"))) {
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
