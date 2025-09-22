# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2174.1");
  script_cve_id("CVE-2015-20107", "CVE-2018-25032");
  script_tag(name:"creation_date", value:"2022-06-27 04:38:24 +0000 (Mon, 27 Jun 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 17:55:33 +0000 (Wed, 09 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2174-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222174-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python39' package(s) announced via the SUSE-SU-2022:2174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python39 fixes the following issues:

CVE-2015-20107: avoid command injection in the mailcap module
 (bsc#1198511).

Update to 3.9.13:
 - Core and Builtins
 - gh-92311: Fixed a bug where setting frame.f_lineno to jump
 over a list comprehension could misbehave or crash.
 - gh-92112: Fix crash triggered by an evil custom mro() on a metaclass.
 - gh-92036: Fix a crash in subinterpreters related to the garbage
 collector. When a subinterpreter is deleted, untrack all objects
 tracked by its GC. To prevent a crash in deallocator functions
 expecting objects to be tracked by the GC, leak a strong reference
 to these objects on purpose, so they are never deleted and their
 deallocator functions are not called. Patch by Victor Stinner.
 - gh-91421: Fix a potential integer overflow in _Py_DecodeUTF8Ex.
 - bpo-46775: Some Windows system error codes(>= 10000) are now mapped
 into the correct errno and may now raise a subclass of OSError.
 Patch by Dong-hee Na.
 - bpo-46962: Classes and functions that unconditionally declared their
 docstrings ignoring the
 --without-doc-strings compilation flag no longer do so.
 - The classes affected are pickle.PickleBuffer,
 testcapi.RecursingInfinitelyError, and types.GenericAlias.
 - The functions affected are 24 methods in ctypes.
 - Patch by Oleg Iarygin.
 - bpo-36819: Fix crashes in built-in encoders with error handlers that
 return position less or equal than the starting position of
 non-encodable characters.
 - Library
 - gh-91581: utcfromtimestamp() no longer attempts to resolve fold in
 the pure Python implementation, since the fold is never 1 in UTC. In
 addition to being slightly faster in the common case, this also
 prevents some errors when the timestamp is close to datetime.min.
 Patch by Paul Ganssle.
 - gh-92530: Fix an issue that occurred after interrupting
 threading.Condition.notify().
 - gh-92049: Forbid pickling constants re._constants.SUCCESS etc.
 Previously, pickling did not fail, but the result could not be
 unpickled.
 - bpo-47029: Always close the read end of the pipe used by
 multiprocessing.Queue after the last write of buffered data to the
 write end of the pipe to avoid BrokenPipeError at garbage collection
 and at multiprocessing.Queue.close() calls. Patch by Gery Ogam.
 - gh-91910: Add missing f prefix to f-strings in error messages from
 the multiprocessing and asyncio modules.
 - gh-91810: ElementTree method write() and function tostring() now use
 the text file''s encoding ('UTF-8' if not available) instead of
 locale encoding in XML declaration when encoding='unicode' is
 specified.
 - gh-91832: Add required attribute to argparse.Action repr
 output.
 - gh-91734: Fix OSS audio support on Solaris.
 - gh-91700: Compilation of regular expression containing a conditional
 expression (?(group)...) now raises an appropriate re.error if the
 group number refers to not defined group. Previously an ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python39' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0", rpm:"libpython3_9-1_0~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython3_9-1_0-debuginfo", rpm:"libpython3_9-1_0-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39", rpm:"python39~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base", rpm:"python39-base~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-base-debuginfo", rpm:"python39-base-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-core-debugsource", rpm:"python39-core-debugsource~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses", rpm:"python39-curses~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-curses-debuginfo", rpm:"python39-curses-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm", rpm:"python39-dbm~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-dbm-debuginfo", rpm:"python39-dbm-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debuginfo", rpm:"python39-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-debugsource", rpm:"python39-debugsource~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-devel", rpm:"python39-devel~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-idle", rpm:"python39-idle~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk", rpm:"python39-tk~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tk-debuginfo", rpm:"python39-tk-debuginfo~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python39-tools", rpm:"python39-tools~3.9.13~150300.4.13.1", rls:"SLES15.0SP3"))) {
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
