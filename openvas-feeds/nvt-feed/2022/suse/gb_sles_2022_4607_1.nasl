# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4607.1");
  script_cve_id("CVE-2022-1708");
  script_tag(name:"creation_date", value:"2022-12-23 04:18:17 +0000 (Fri, 23 Dec 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-14 15:44:06 +0000 (Tue, 14 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4607-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224607-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon' package(s) announced via the SUSE-SU-2022:4607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon fixes the following issues:

conmon was updated to version 2.1.5:

don't leak syslog_identifier

logging: do not read more that the buf size

logging: fix error handling

Makefile: Fix install for FreeBSD

signal: Track changes to get_signal_descriptor in the FreeBSD version

Packit: initial enablement

Update to version 2.1.4:

Fix a bug where conmon crashed when it got a SIGCHLD

update to 2.1.3:

Stop using g_unix_signal_add() to avoid threads

Rename CLI optionlog-size-global-max to log-global-size-max

Update to version 2.1.2:

add log-global-size-max option to limit the total output conmon
 processes (CVE-2022-1708 bsc#1200285)

journald: print tag and name if both are specified

drop some logs to debug level

Update to version 2.1.0

logging: buffer partial messages to journald

exit: close all fds >= 3

fix: cgroup: Free memory_cgroup_file_path if open fails.

Update to version 2.0.32

Fix: Avoid mainfd_std{in,out} sharing the same file descriptor.

exit_command: Fix: unset subreaper attribute before running exit command

Update to version 2.0.31 logging: new mode -l passthrough

ctr_logs: use container name or ID as SYSLOG_IDENTIFIER for journald

conmon: Fix: free userdata files before exec cleanup");

  script_tag(name:"affected", value:"'conmon' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Containers 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.5~150300.8.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.5~150300.8.6.1", rls:"SLES15.0SP3"))) {
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
