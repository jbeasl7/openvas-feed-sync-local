# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123514");
  script_cve_id("CVE-2013-0281");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-1635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1635");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1635.html");
  script_xref(name:"URL", value:"https://raw.github.com/ClusterLabs/pacemaker/master/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker' package(s) announced via the ELSA-2013-1635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.1.10-14]
- Log: crmd: Supply arguments in the correct order
 Resolves: rhbz#996850
- Fix: Invalid formatting of log message causes crash
 Resolves: rhbz#996850

[1.1.10-13]
- Fix: cman: Start clvmd and friends from the init script if enabled

[1.1.10-12]
- Fix: Consistently use 'Slave' as the role for unpromoted master/slave resources
 Resolves: rhbz#1011618
- Fix: pengine: Location constraints with role=Started should prevent masters from running at all
 Resolves: rhbz#902407
- Fix: crm_resource: Observe --master modifier for --move
 Resolves: rhbz#902407

[1.1.10-11]
+ Fix: cman: Do not start pacemaker if cman startup fails
 + Fix: Fencing: Observe pcmk_host_list during automatic unfencing
 Resolves: rhbz#996850

[1.1.10-10]
- Remove unsupported resource agent
 Resolves: rhbz#1005678
- Provide a meaningful error if --master is used for primitives and groups

[1.1.10-9]
+ Fix: xml: Location constraints are allowed to specify a role
 + Bug rhbz#902407 - crm_resource: Handle --ban for master/slave resources as advertised
 Resolves: rhbz#902407

[1.1.10-8]
+ Fix: mcp: Remove LSB hints that instruct chkconfig to start pacemaker at boot time
 Resolves: rhbz#997346

[1.1.10-7]
+ Fencing: Support agents that need the host to be unfenced at startup
 Resolves: rhbz#996850
 + Fix: crm_report: Collect corosync quorum data
 Resolves: rhbz#989292

[1.1.10-6]
- Regenerate patches to have meaningful names

[1.1.10-5]
+ Fix: systemd: Prevent glib assertion - only call g_error_free with non-NULL arguments
 + Fix: systemd: Prevent additional use-of-NULL assertions in g_error_free
 + Fix: logging: glib CRIT messages should not produce core files in the background
 + Fix: crmd: Correctly update the history cache when recurring ops change their return code
 + Log: crm_mon: Unmangle the output for failed operations
 + Log: cib: Correctly log short-form xml diffs
 + Log: pengine: Better indicate when a resource has failed

[1.1.10-4]
+ Fix: crmd: Prevent crash by passing log arguments in the correct order
 + Fix: pengine: Do not re-allocate clone instances that are blocked in the Stopped state
 + Fix: pengine: Do not allow colocation with blocked clone instances

[1.1.10-3]
+ Fix: pengine: Do not restart resources that depend on unmanaged resources
 + Fix: crmd: Prevent recurring monitors being cancelled due to notify operations

[1.1.10-2]
- Drop rgmanager 'provides' directive

[1.1.10-1]
- Update source tarball to revision: Pacemaker-1.1.10
- See included ChangeLog file or [link moved to references] for full details

- Resolves: rhbz#891766
- Resolves: rhbz#902407
- Resolves: rhbz#908450
- Resolves: rhbz#913093
- Resolves: rhbz#951340
- Resolves: rhbz#951371
- Related: rhbz#987355");

  script_tag(name:"affected", value:"'pacemaker' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"pacemaker", rpm:"pacemaker~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cli", rpm:"pacemaker-cli~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cluster-libs", rpm:"pacemaker-cluster-libs~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cts", rpm:"pacemaker-cts~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-doc", rpm:"pacemaker-doc~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-libs", rpm:"pacemaker-libs~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-libs-devel", rpm:"pacemaker-libs-devel~1.1.10~14.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-remote", rpm:"pacemaker-remote~1.1.10~14.el6", rls:"OracleLinux6"))) {
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
