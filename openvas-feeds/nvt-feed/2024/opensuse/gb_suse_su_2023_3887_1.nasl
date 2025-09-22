# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833495");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-38403");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-15 17:26:21 +0000 (Tue, 15 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:54:32 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for iperf (SUSE-SU-2023:3887-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3887-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DCUKFRL7NSEPG6GP3NW3TXQSX6QXAG6A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iperf'
  package(s) announced via the SUSE-SU-2023:3887-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for iperf fixes the following issues:

  * update to 3.15 (bsc#1215662, ESNET-SECADV-2023-0002):

  * Several bugs that could allow the iperf3 server to hang waiting for input on
      the control connection has been fixed (ESnet Software Security Advisory
      ESNET-SECADV-2023-0002)

  * A bug that caused garbled output with UDP tests on 32-bit hosts has been
      fixed (PR #1554, PR #1556). This bug was introduced in iperf-3.14.

  * A bug in counting UDP messages has been fixed

  * update to 3.14 (bsc#1213430, CVE-2023-38403):

  * fixes a memory allocation hazard that allowed a remote user to crash an
      iperf3 process

  * update to 3.13:

  * Added missing bind_dev getter and setter.

  * a fix for A resource leak bug in function iperf_create_pidfile (#1443)

  * doc: Fix copy-and-paste error leading to wrong error message

  * Fix crash on rcv-timeout with JSON logfile

  * update to 3.12:

  * cJSON has been updated to version 1.7.15 (#1383).

  * The --bind  host % dev  option syntax now works properly (#1360 /

  * A server-side file descriptor leak with the --logfile option has been fixed
      (#1369 / #1360 / #1369 / #1389 / #1393).

  * A bug that caused some large values from TCP_INFO to be misprinted as
      negative numbers has been fixed (#1372).

  * Using the -k or -n flags with --reverse no longer leak into future tests
      (#1363 / #1364).

  * There are now various debug level options available with the --debug
      option. These can be used to adjust the amount of debugging output (#1327).

  * A new --snd-timeout option has been added to set a termination timeout for
      idle TCP connections (#1215 / #1282).

  * iperf3 is slightly more robust to out-of-order packets during UDP connection
      setup in --reverse mode (#914 / #1123 / #1182 / #1212 /

  * iperf3 will now use different ports for each direction when the --cport and

  - -bdir options are set (#1249 / #1259).

  * The iperf3 server will now exit if it can't open its log file

  * Various help message and output fixes have been made (#1299 /

  * Various compiler warnings have been fixed (#1211 / #1316).

  * Operation of bootstrap.sh has been fixed and simplified (#1335 /

  * Flow label support / compatibility under Linux has been improved

  * Various minor memory leaks have been fixed (#1332 / #1333).

  * A getter/setter has been added for the bind_port parameter (--cport option).
      (#1303, #1305)
  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'iperf' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"iperf-debuginfo", rpm:"iperf-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-devel", rpm:"iperf-devel~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0-debuginfo", rpm:"libiperf0-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debugsource", rpm:"iperf-debugsource~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debuginfo", rpm:"iperf-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-devel", rpm:"iperf-devel~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0-debuginfo", rpm:"libiperf0-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debugsource", rpm:"iperf-debugsource~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.15~150000.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"iperf-debuginfo", rpm:"iperf-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-devel", rpm:"iperf-devel~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0-debuginfo", rpm:"libiperf0-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debugsource", rpm:"iperf-debugsource~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debuginfo", rpm:"iperf-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-devel", rpm:"iperf-devel~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0-debuginfo", rpm:"libiperf0-debuginfo~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-debugsource", rpm:"iperf-debugsource~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.15~150000.3.6.1", rls:"openSUSELeap15.5"))) {
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
