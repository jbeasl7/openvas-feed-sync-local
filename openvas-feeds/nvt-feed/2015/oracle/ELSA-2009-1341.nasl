# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122446");
  script_cve_id("CVE-2008-4579", "CVE-2008-6552");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:31 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1341");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cman' package(s) announced via the ELSA-2009-1341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.0.115-1]
- RSA II fencing agent has been fixed.
- Resolves: rhbz#493802

[2.0.114-1]
- local variable 'verbose_filename' referenced before assignment has been fixed
- RSA II fencing agent has been fixed.
- Resolves: rhbz#493802 rhbz#514758

[2.0.113-1]
- Limitations with 2-node fence_scsi are now properly documented in the man
 page.
- Resolves: rhbz#512998

[2.0.112-1]
- The pexpect exception is now properly checked in fence agents.
- Resolves: rhbz#501586

[2.0.111-1]
- cman_tool leave remove does now properly reduces quorum.
- Resolves: rhbz#505258

[2.0.110-1]
- Updated fence_lpar man page to remove options that do not yet exist.
- Resolves: rhbz#498045

[2.0.108-1]
- A semaphore leak in cman has been fixed.
- Resolves: rhbz#505594

[2.0.107-1]
- Added man page for lpar fencing agent (fence_lpar).
- Resolves: rhbz#498045

[2.0.106-1]
- The lssyscfg command can take longer than the shell timeout which will
 cause fencing to fail, we now wait longer for the lssyscfg command to
 complete.
- Resolves: rhbz#504705

[2.0.105-1]
- The fencing agents no longer fail with pexpect exceptions.
- Resolves: rhbz#501586

[2.0.104-1]
- Broadcast communications are now possible with cman
- fence_lpar can now login to IVM systems
- Resolves: rhbz#502674 rhbz#492808

[2.0.103-1]
- fence_apc no longer fails with a pexpect exception
- symlink vulnerabilities in fance_apc_snmp were fixed
- The virsh fencing agent was added.
- Resolves: rhbz#496629 rhbz#498952 rhbz#501586

[2.0.102-1]
- Correct return code is checked during disk scanning check.
- Resolves: rhbz#484956

[2.0.101-1]
- The SCSI fence agent now verifies that sg_persist is installed properly.
- The DRAC5 fencing agent now properly handles a modulename.
- QDisk now logs warning messages if it appears it's I/O to shared storage
 is hung.
- Resolves: rhbz#496724 rhbz#500450 rhbz#500567

[2.0.100-1]
- Support has been added for ePowerSwitch 8+ devices
- cluster.conf files can now have more than 52 entries inside a block inside
[block]
- The output of the group_tool dump sub commands are no longer NULL padded.
- Using device='' instead of label='' no longer causes qdiskd to incorrectly
 exit
- The IPMI fencing agent has been modified to timeout after 10 seconds. It is
 also now possible to specify a different timeout with the '-t' option.
- The IPMI fencing agent now allows punctuation in the password
- Quickly starting and stopping the cman service no longer causes the cluster
 membership to become inconsistent across the cluster
- An issue with lock syncing causing 'receive_own from ...' errors in syslog
 has been fixed
- An issue which caused gfs_controld to segfault when mounting hundreds of
 filesystems has been fixed
- The LPAR fencing agent now properly reports status when an LPAR is in
 Open Firmware
- The APC SNMP fencing agent now properly recognizes outletStatusOn and
 outletStatusOff returns codes from the SNMP agent
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'cman' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cman", rpm:"cman~2.0.115~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cman-devel", rpm:"cman-devel~2.0.115~1.el5", rls:"OracleLinux5"))) {
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
