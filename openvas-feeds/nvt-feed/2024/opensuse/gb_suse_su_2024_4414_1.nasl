# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856876");
  script_cve_id("CVE-2022-48064");
  script_tag(name:"creation_date", value:"2024-12-24 05:00:23 +0000 (Tue, 24 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:15:15 +0000 (Sat, 26 Aug 2023)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4414-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244414-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220490");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/020047.html");
  script_xref(name:"URL", value:"https://no-color.org/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the SUSE-SU-2024:4414-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:

Mention changes in GDB 14:

* GDB now supports the AArch64 Scalable Matrix Extension 2
 (SME2), which includes a new 512 bit lookup table register
 named ZT0.
* GDB now supports the AArch64 Scalable Matrix Extension (SME),
 which includes a new matrix register named ZA, a new thread
 register TPIDR2 and a new vector length register SVG
 (streaming vector granule). GDB also supports tracking ZA
 state across signal frames. Some features are still under
 development or are dependent on ABI specs that are still in
 alpha stage. For example, manual function calls with ZA state
 don't have any special handling, and tracking of SVG changes
 based on DWARF information is still not implemented, but there
 are plans to do so in the future.
* GDB now recognizes the NO_COLOR environment variable and
 disables styling according to the spec. See
 [link moved to references]. Styling can be re-enabled with
 'set style enabled on'.
* The AArch64 'org.gnu.gdb.aarch64.pauth' Pointer Authentication
 feature string has been deprecated in favor of the
 'org.gnu.gdb.aarch64.pauth_v2' feature string.
* GDB now has some support for integer types larger than 64 bits.
* Multi-target feature configuration.
 GDB now supports the individual configuration of remote
 targets' feature sets. Based on the current selection of a
 target, the commands 'set remote <name>-packet (on<pipe>off<pipe>auto)'
 and 'show remote <name>-packet' can be used to configure a
 target's feature packet and to display its configuration,
 respectively.
* GDB has initial built-in support for the Debugger Adapter
 Protocol.
* For the break command, multiple uses of the 'thread' or 'task'
 keywords will now give an error instead of just using the
 thread or task id from the last instance of the keyword. E.g.:
 break foo thread 1 thread 2
 will now give an error rather than using 'thread 2'.
* For the watch command, multiple uses of the 'task' keyword will
 now give an error instead of just using the task id from the
 last instance of the keyword. E.g.:
 watch my_var task 1 task 2
 will now give an error rather than using 'task 2'. The
 'thread' keyword already gave an error when used multiple times
 with the watch command, this remains unchanged.
* The 'set print elements' setting now helps when printing large
 arrays. If an array would otherwise exceed max-value-size, but
 'print elements' is set such that the size of elements to print
 is less than or equal to 'max-value-size', GDB will now still
 print the array, however only 'max-value-size' worth of data
 will be added into the value history.
* For both the break and watch commands, it is now invalid to use
 both the 'thread' and 'task' keywords within the same command.
 For example the following commnds will now give an error:
 break foo thread 1 task 1
 watch var thread 2 task 3
* The printf command now accepts a '%V' ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gdb' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~14.2~150400.15.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-testresults", rpm:"gdb-testresults~14.2~150400.15.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdbserver", rpm:"gdbserver~14.2~150400.15.20.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~14.2~150400.15.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-testresults", rpm:"gdb-testresults~14.2~150400.15.20.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdbserver", rpm:"gdbserver~14.2~150400.15.20.1", rls:"openSUSELeap15.6"))) {
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
