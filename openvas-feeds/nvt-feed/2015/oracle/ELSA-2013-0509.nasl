# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123718");
  script_cve_id("CVE-2012-4517", "CVE-2012-4518");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:37 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0509");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0509.html");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild");
  script_xref(name:"URL", value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ibacm, ibsim, ibutils, infiniband-diags, infinipath-psm, libibmad, libibumad, libibverbs, libmlx4, librdmacm, opensm, rdma' package(s) announced via the ELSA-2013-0509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ibacm
[1.0.8-0.git7a3adb7]
- Update to latest upstream via git repo
- Resolves: bz866222, bz866223

ibsim
[0.5-7]
- Bump and rebuild against latest opensm
- Related: bz756396

ibutils
[1.5.7-7]
- Bump and rebuild against latest opensm
- Related: bz756396

infiniband-diags
[1.5.12-5]
- Bump and rebuild against latest opensm
- Pick up fixes done for rhel5.9
- Related: bz756396

[1.5.12-4]
- Update the all_hcas patch to resolve several problems
- Give a simple help message to the ibnodes script
- Resolves: bz818606, bz847129

infinipath-psm
[3.0.1-115.1015_open.1]
- New upstream release
 Resolves: rhbz818789

libibmad
[1.3.9-1]
- Update to latest upstream version (more SRIOV support)
- Related: bz756396

[1.3.8-1]
- Update to latest upstream version (for FDR link speed support)
- Related: bz750609

[1.3.7-1]
- Update to latest upstream version (1.3.4 -> 1.3.7)
- Related: bz725016

[1.3.4-1]
- New upstream version

[1.3.3-2]
- ExcludeArch s390(x) as there's no hardware support there

[1.3.3-1]
- Update to latest upstream releasee

[1.3.2-2]
- Rebuilt for [link moved to references]

[1.3.2-1]
- Update to latest upstream version
- Require the same version of libibumad as our version

[1.3.1-1]
- Update to latest upstream version

[1.2.0-3]
- Rebuilt against libtool 2.2

[1.2.0-2]
- Rebuilt for [link moved to references]

[1.2.0-1]
- Initial package for Fedora review process

libibumad
[1.3.8-1]
- Update to latest upstream releasee (more SRIOV support)
- Related: bz756396

[1.3.7-1]
- Update to latest upstream version (1.3.4 -> 1.3.7)
- Related: bz725016

[1.3.4-1]
- New upstream releasee

[1.3.3-2]
- ExcludeArch s390(x) as there is no hardware support there

[1.3.3-1]
- Update to latest upstream version

[1.3.2-3]
- Rebuilt for [link moved to references]

[1.3.2-2]
- Forgot to remove both instances of the libibcommon requires
- Add build requires on glibc-static

[1.3.2-1]
- Update to latest upstream version
- Remove requirement on libibcommon since that library is no longer needed
- Fix a problem with man page listing

[1.3.1-1]
- Update to latest upstream version

[1.2.0-3]
- Rebuilt against libtool 2.2

[1.2.0-2]
- Rebuilt for [link moved to references]

[1.2.0-1]
- Initial package for Fedora review process

libibverbs
[1.1.6-5]
- Don't print link state on iWARP links as it's always invalid
- Don't try to do ud transfers in excess of port MTU
- Resolves: bz822781

libmlx4
[1.0.4-1]
- Update to latest upstream version
- Related: bz756396

librdmacm
[1.0.17-0.git4b5c1aa]
- Pre-releasee version of 1.0.17
- Resolves a CVE vulnerability between librdmacm and ibacm
- Fixes various minor bugs in sample programs
- Resolves: bz866221, bz816074

opensm
[3.3.15-1]
- Update to latest upstream source (adds more SRIOV support)
- Fix init script when no config files are present
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ibacm, ibsim, ibutils, infiniband-diags, infinipath-psm, libibmad, libibumad, libibverbs, libmlx4, librdmacm, opensm, rdma' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ibacm", rpm:"ibacm~1.0.8~0.git7a3adb7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibacm-devel", rpm:"ibacm-devel~1.0.8~0.git7a3adb7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibsim", rpm:"ibsim~0.5~7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibutils", rpm:"ibutils~1.5.7~7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibutils-devel", rpm:"ibutils-devel~1.5.7~7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ibutils-libs", rpm:"ibutils-libs~1.5.7~7.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infiniband-diags", rpm:"infiniband-diags~1.5.12~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infiniband-diags-devel", rpm:"infiniband-diags-devel~1.5.12~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infiniband-diags-devel-static", rpm:"infiniband-diags-devel-static~1.5.12~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infinipath-psm", rpm:"infinipath-psm~3.0.1~115.1015_open.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"infinipath-psm-devel", rpm:"infinipath-psm-devel~3.0.1~115.1015_open.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibmad", rpm:"libibmad~1.3.9~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibmad-devel", rpm:"libibmad-devel~1.3.9~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibmad-static", rpm:"libibmad-static~1.3.9~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibumad", rpm:"libibumad~1.3.8~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibumad-devel", rpm:"libibumad-devel~1.3.8~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibumad-static", rpm:"libibumad-static~1.3.8~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs", rpm:"libibverbs~1.1.6~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-devel", rpm:"libibverbs-devel~1.1.6~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-devel-static", rpm:"libibverbs-devel-static~1.1.6~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libibverbs-utils", rpm:"libibverbs-utils~1.1.6~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlx4", rpm:"libmlx4~1.0.4~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmlx4-static", rpm:"libmlx4-static~1.0.4~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm", rpm:"librdmacm~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-devel", rpm:"librdmacm-devel~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-static", rpm:"librdmacm-static~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librdmacm-utils", rpm:"librdmacm-utils~1.0.17~0.git4b5c1aa.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensm", rpm:"opensm~3.3.15~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensm-devel", rpm:"opensm-devel~3.3.15~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensm-libs", rpm:"opensm-libs~3.3.15~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensm-static", rpm:"opensm-static~3.3.15~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rdma", rpm:"rdma~3.6~1.0.2.el6", rls:"OracleLinux6"))) {
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
