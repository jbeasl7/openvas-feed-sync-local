# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123328");
  script_cve_id("CVE-2013-2930", "CVE-2013-4579", "CVE-2014-1690");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:20 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2014-3070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3070");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-44.el6uek, dtrace-modules-3.8.13-44.el7uek, kernel-uek' package(s) announced via the ELSA-2014-3070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-44]
- net: Use netlink_ns_capable to verify the permissions of netlink messages (Eric W. Biederman) [Orabug: 19404229] {CVE-2014-0181}
- net: Add variants of capable for use on netlink messages (Eric W. Biederman) [Orabug: 19404229]
- net: Add variants of capable for use on on sockets (Eric W. Biederman) [Orabug: 19404229]
- netlink: Rename netlink_capable netlink_allowed (Eric W. Biederman) [Orabug: 19404229]
- sctp: Fix sk_ack_backlog wrap-around problem (Xufeng Zhang) [Orabug: 19404238] {CVE-2014-4667}
- Revert 'xen/fb: allow xenfb initialization for hvm guests' (Vaughan Cao) [Orabug: 19320529]

[3.8.13-43]
- init: fix in-place parameter modification regression (Krzysztof Mazur) [Orabug: 18954967]
- drivers: scsi: storvsc: Correctly handle TEST_UNIT_READY failure (K. Y. Srinivasan) [Orabug: 19280065]
- drivers: scsi: storvsc: Set srb_flags in all cases (K. Y. Srinivasan) [Orabug: 19280065]
- Drivers: scsi: storvsc: Implement a timedout handler (K. Y. Srinivasan) [Orabug: 19280065]
- Drivers: scsi: storvsc: Fix a bug in handling VMBUS protocol version (K. Y. Srinivasan) [Orabug: 19280065]
- Drivers: scsi: storvsc: Filter commands based on the storage protocol version (K. Y. Srinivasan) [Orabug: 19280065]
- Drivers: scsi: storvsc: Set cmd_per_lun to reflect value supported by the Host (K. Y. Srinivasan) [Orabug: 19280065]
- Drivers: scsi: storvsc: Change the limits to reflect the values on the host (K. Y. Srinivasan) [Orabug: 19280065]

[3.8.13-42]
- filter: prevent nla extensions to peek beyond the end of the message (Mathias Krause) [Orabug: 19315780] {CVE-2014-3144} {CVE-2014-3145}

[3.8.13-41]
- rds: Lost locking in loop connection freeing (Pavel Emelyanov) [Orabug: 19124446]
- ocfs2/o2net: incorrect to terminate accepting connections loop upon rejecting an invalid one (Tariq Saeed) [Orabug: 19296823]
- xen/pciback: Don't deadlock when unbinding. (Konrad Rzeszutek Wilk) [Orabug: 19296592]
- PCI: Split out pci_dev lock/unlock and save/restore (Alex Williamson) [Orabug: 19296592]

[3.8.13-40]
- l2tp: fix an unprivileged user to kernel privilege escalation (Sasha Levin) [Orabug: 19228689] {CVE-2014-4943} {CVE-2014-4943}
- ptrace,x86: force IRET path after a ptrace_stop() (Tejun Heo) [Orabug: 19222017] {CVE-2014-4699}
- mpt3sas: Rework the MSI-X code to work on systems with many processors (Martin K. Petersen) [Orabug: 18182490]
- mpt2sas: Rework the MSI-X code to work on systems with many processors (Martin K. Petersen) [Orabug: 18182490]
- mpt3sas: Bump mpt3sas driver version to 04.100.00.00 (Reddy, Sreekanth) [Orabug: 19015667]
- mpt3sas: Added Reply Descriptor Post Queue (RDPQ) Array support (Reddy, Sreekanth) [Orabug: 19015667]
- mpt3sas: Bump mpt3sas driver version to 03.100.00.00 (Reddy, Sreekanth) [Orabug: 19015667]
- mpt3sas: Added OEM branding Strings (Reddy, Sreekanth) [Orabug: 19015667]
- mpt3sas: MPI2.5 Rev H (2.5.3) specifications (Reddy, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-44.el6uek, dtrace-modules-3.8.13-44.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-44.el6uek", rpm:"dtrace-modules-3.8.13-44.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~44.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-44.el7uek", rpm:"dtrace-modules-3.8.13-44.el7uek~0.4.3~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~44.el7uek", rls:"OracleLinux7"))) {
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
