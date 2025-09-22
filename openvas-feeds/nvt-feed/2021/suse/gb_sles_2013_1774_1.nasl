# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.1774.1");
  script_cve_id("CVE-2013-1432", "CVE-2013-1442", "CVE-2013-1918", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4416");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:1774-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:1774-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20131774-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2013:1774-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XEN has been updated to version 4.2.3 c/s 26170, fixing various bugs and security issues.

 * CVE-2013-4416: XSA-72: Fixed ocaml xenstored that mishandled oversized message replies
 * CVE-2013-4355: XSA-63: Fixed information leaks through I/O instruction emulation
 * CVE-2013-4361: XSA-66: Fixed information leak through fbld instruction emulation
 * CVE-2013-4368: XSA-67: Fixed information leak through outs instruction emulation
 * CVE-2013-4369: XSA-68: Fixed possible null dereference when parsing vif ratelimiting info
 * CVE-2013-4370: XSA-69: Fixed misplaced free in ocaml xc_vcpu_getaffinity stub
 * CVE-2013-4371: XSA-70: Fixed use-after-free in libxl_list_cpupool under memory pressure
 * CVE-2013-4375: XSA-71: xen: qemu disk backend (qdisk)
resource leak
 * CVE-2013-1442: XSA-62: Fixed information leak on AVX and/or LWP capable CPUs
 * CVE-2013-1432: XSA-58: Page reference counting error due to XSA-45/CVE-2013-1918 fixes.

Various bugs have also been fixed:

 * Boot failure with xen kernel in UEFI mode with error
'No memory for trampoline' (bnc#833483)
 * Improvements to block-dmmd script (bnc#828623)
 * MTU size on Dom0 gets reset when booting DomU with e1000 device (bnc#840196)
 * In HP's UEFI x86_64 platform and with xen environment, in booting stage, xen hypervisor will panic.
(bnc#833251)
 * Xen: migration broken from xsave-capable to xsave-incapable host (bnc#833796)
 * In xen, 'shutdown -y 0 -h' cannot power off system
(bnc#834751)
 * In HP's UEFI x86_64 platform with xen environment,
xen hypervisor will panic on multiple blades nPar.
(bnc#839600)
 * vcpus not started after upgrading Dom0 from SLES 11 SP2 to SP3 (bnc#835896)
 * SLES 11 SP3 Xen security patch does not automatically update UEFI boot binary (bnc#836239)
 * Failed to setup devices for vm instance when start multiple vms simultaneously (bnc#824676)
 * SLES 9 SP4 guest fails to start after upgrading to SLES 11 SP3 (bnc#817799)
 * Various upstream fixes have been included.

Security Issues:

 * CVE-2013-1432
>
 * CVE-2013-1442
>
 * CVE-2013-1918
>
 * CVE-2013-4355
>
 * CVE-2013-4361
>
 * CVE-2013-4368
>
 * CVE-2013-4369
>
 * CVE-2013-4370
>
 * CVE-2013-4371
>
 * CVE-2013-4375
>
 * CVE-2013-4416
>");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.3_02_3.0.93_0.8~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.3_02_3.0.93_0.8~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.2.3_02~0.7.1", rls:"SLES11.0SP3"))) {
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
