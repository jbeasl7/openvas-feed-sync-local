# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02749.1");
  script_cve_id("CVE-2025-54349", "CVE-2025-54350", "CVE-2025-54351");
  script_tag(name:"creation_date", value:"2025-08-12 04:11:29 +0000 (Tue, 12 Aug 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-05 16:36:43 +0000 (Tue, 05 Aug 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02749-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02749-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502749-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247522");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041156.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iperf' package(s) announced via the SUSE-SU-2025:02749-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for iperf fixes the following issues:

- update to 3.19.1:
 * CVE-2025-54351: Fixed buffer overflow in net.c (bsc#1247522)
 * CVE-2025-54350: Fixed Base64Decode assertion failure and application
 exit upon a malformed authentication attempt (bsc#1247520)
 * CVE-2025-54349: Fixed off-by-one error and resultant heap-based
 buffer overflow (bsc#1247519)

- update to 3.19:
 * iperf3 now supports the use of Multi-Path TCP (MPTCPv1) on Linux
 with the use of the `-m` or `--mptcp` flag. (PR #1661)
 * iperf3 now supports a `--cntl-ka` option to enable TCP keepalives
 on the control connection. (#812, #835, PR #1423)
 * iperf3 now supports the `MSG_TRUNC` receive option, specified by
 the `--skip-rx-copy`. This theoretically improves the rated
 throughput of tests at high bitrates by not delivering network
 payload data to userspace. (#1678, PR #1717)
 * A bug that caused the bitrate setting to be ignored when bursts
 are set, has been fixed. (#1773, #1820, PR #1821, PR #1848)
 * The congestion control protocol setting, if used, is now
 properly reset between tests. (PR #1812)
 * iperf3 now exits with a non-error 0 exit code if exiting via a
 `SIGTERM`, `SIGHUP`, or `SIGINT`. (#1009, PR# 1829)
 * The current behavior of iperf3 with respect to the `-n` and `-k`
 options is now documented as correct. (#1768, #1775, #596, PR #1800)");

  script_tag(name:"affected", value:"'iperf' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"iperf", rpm:"iperf~3.19.1~150000.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iperf-devel", rpm:"iperf-devel~3.19.1~150000.3.15.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libiperf0", rpm:"libiperf0~3.19.1~150000.3.15.1", rls:"openSUSELeap15.6"))) {
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
