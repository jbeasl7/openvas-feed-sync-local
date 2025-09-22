# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123526");
  script_cve_id("CVE-2012-4516", "CVE-2013-2561");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1661)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1661");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1661.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ibutils, infinipath-psm, libibverbs, libmlx4, librdmacm, mpitests, mstflint, openmpi, perftest, qperf, rdma' package(s) announced via the ELSA-2013-1661 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ibutils
[1.5.7-8]
- Add the -output patch to have programs use /var/cache/ibutils
 instead of /tmp
 Resolves: bz958569

infinipath-psm
* Thu Jan 24 2013 Jay Fenlason - Put the udev rules file in the right place
 Resolves: rhbz866732
- include a patch from upstream to fix undefined references
 Resolves: rhbz887730
 [3.0.1-115.1015_open.1]
- New upstream release
 Resolves: rhbz818789
 [ 2.9-926.1005_open.2]
- Add the udev rules file to close
 Resolves: rhbz747406
 [2.9-926.1005_open.1]
- New upstream version.
 Resolves: rhbz635915
 * Fri Nov 05 2010 Jay Fenlason - Include the -execstack patch to get libinfinipath.so correctly
 labeled as not executing the stack.
 Resolves: rhbz612936
 [1.13-2]
- Use macros for lib and include directories, and include dist tag in
 releasee field.
- Corrected License field.
- Corrected Requires lines for libuuid.
- Add Exclusive-arch x86_64
 Related: rhbz570274
 [1.13-1]
- Initial build.
 libibverbs
[1.1.7-1]
- Update to latest upstream releasee
- Remove patches that are now part of upstream
- Fix ibv_srq_pingpong with negative value to -s option
- Resolves: bz879191
 libmlx4
[1.0.5-4.el6.1]
- Fix dracut module for compatibility with RHEL6 version of dracut.
- Resolves: bz789121
 [1.0.5-4]
- Add dracut module
- Fix URL
 [1.0.5-3]
- Reduce the dependencies of the setup script even further, it no longer
 needs grep
 [1.0.5-2]
- The setup script needs to have execute permissions
 [1.0.5-1]
- Update to latest upstream
- Drop awk based setup for a bash based setup, making including
 the setup code on an initramfs easier
- Modernize spec file
- Related: bz950915
 librdmacm
[1.0.17-1]
- Official 1.0.17 releasee
- The fix to bug 866221 got kicked back as incomplete last time, fix
 it for real this time.
- Intel adapters that use the qib driver don't like using inline data,
 so use a memory region that is registered instead
- Resolves: bz866221, bz828071
 mpitests
[3.2-9]
- Backport fixes from RHEL-7
 Resolves: rhbz1002332
 [3.2-7]
- include BuildRequires: hwloc-devel from RHEL-7.0
- Add win_free patch to close
 Resolves: rhbz734023
 mstflint
[3.0-0.6.g6961daa.1]
- Update to newer tarball that resolves licensing issues with the last
 tarball
- Related: bz818183
 [3.0-0.5.gff93670.1]
- Update to latest upstream version, which includes ConnectIB support
- Resolves: bz818183
 openmpi
[1.5.4-2.0.1]
- Obsolete openmpi-psm-devel for 32bit
 [1.5.4-2]
- Fix the build process by getting rid of the -build patch
 and autogen to fix
 Resolves: rhbz749115
 perftest
[2.0-2]
- Fix rpmdiff detected error. Upstream overrode our cflags so stack
 protector got turned off.
- Related: bz806183
 [2.0-1]
- Update to latest upstream releasee
- We had to drop ib_clock_test program as no equivalent exists
 in the latest releasee
- Resolves: bz806183, bz806185, bz830099
 [1.3.0-2]
- Update to latest upstream releasee
- No longer strip rocee related code out, we can compile ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ibutils, infinipath-psm, libibverbs, libmlx4, librdmacm, mpitests, mstflint, openmpi, perftest, qperf, rdma' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.5.7~8.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibutils-devel", rpm:"ibutils-devel~1.5.7~8.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.5.7~8.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infinipath-psm", rpm:"infinipath-psm~3.0.1~115.1015_open.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infinipath-psm-devel", rpm:"infinipath-psm-devel~3.0.1~115.1015_open.2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs", rpm:"libibverbs~1.1.7~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-devel", rpm:"libibverbs-devel~1.1.7~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-devel-static", rpm:"libibverbs-devel-static~1.1.7~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-utils", rpm:"libibverbs-utils~1.1.7~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlx4", rpm:"libmlx4~1.0.5~4.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlx4-static", rpm:"libmlx4-static~1.0.5~4.el6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm", rpm:"librdmacm~1.0.17~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-devel", rpm:"librdmacm-devel~1.0.17~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-static", rpm:"librdmacm-static~1.0.17~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-utils", rpm:"librdmacm-utils~1.0.17~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests", rpm:"mpitests~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests-mvapich", rpm:"mpitests-mvapich~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests-mvapich-psm", rpm:"mpitests-mvapich-psm~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests-mvapich2", rpm:"mpitests-mvapich2~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests-mvapich2-psm", rpm:"mpitests-mvapich2-psm~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mpitests-openmpi", rpm:"mpitests-openmpi~3.2~9.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mstflint", rpm:"mstflint~3.0~0.6.g6961daa.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi", rpm:"openmpi~1.5.4~2.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openmpi-devel", rpm:"openmpi-devel~1.5.4~2.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perftest", rpm:"perftest~2.0~2.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qperf", rpm:"qperf~0.4.9~1.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rdma", rpm:"rdma~3.10~3.0.1.el6", rls:"OracleLinux6"))) {
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
