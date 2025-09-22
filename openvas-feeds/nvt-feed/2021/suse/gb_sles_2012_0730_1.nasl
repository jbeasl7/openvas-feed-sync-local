# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0730.1");
  script_cve_id("CVE-2012-0217", "CVE-2012-0218", "CVE-2012-2934");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP2|SLES10\.0SP3|SLES10\.0SP4|SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0730-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120730-1/");
  script_xref(name:"URL", value:"http://support.amd.com/us/Processor_TechDocs/25759.pdf");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2012:0730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three security issues were found in XEN.

Two security issues are fixed by this update:

 *

 CVE-2012-0217: Due to incorrect fault handling in the XEN hypervisor it was possible for a XEN guest domain administrator to execute code in the XEN host environment.

 *

 CVE-2012-0218: Also a guest user could crash the guest XEN kernel due to a protection fault bounce.

The third fix is changing the Xen behaviour on certain hardware:

 *

 CVE-2012-2934: The issue is a denial of service issue on older pre-SVM AMD CPUs (AMD Erratum 121).

 AMD Erratum #121 is described in 'Revision Guide for AMD Athlon 64 and AMD Opteron Processors':
[link moved to references]
 The following 130nm and 90nm (DDR1-only) AMD processors are subject to this erratum:
 o
 First-generation AMD-Opteron(tm) single and dual core processors in either 939 or 940 packages:
 + AMD Opteron(tm) 100-Series Processors
 + AMD Opteron(tm) 200-Series Processors
 + AMD Opteron(tm) 800-Series Processors
 + AMD Athlon(tm) processors in either 754,
939 or 940 packages
 + AMD Sempron(tm) processor in either 754 or 939 packages
 + AMD Turion(tm) Mobile Technology in 754 package
 This issue does not effect Intel processors.
 The impact of this flaw is that a malicious PV guest user can halt the host system.
 As this is a hardware flaw, it is not fixable except by upgrading your hardware to a newer revision, or not allowing untrusted 64bit guestsystems.
 The patch changes the behaviour of the host system booting, which makes it unable to create guest machines until a specific boot option is set.
 There is a new XEN boot option 'allow_unsafe' for GRUB which allows the host to start guests again.
 This is added to /boot/grub/menu.lst in the line looking like this:
 kernel /boot/xen.gz .... allow_unsafe
 Note: .... in this example represents the existing boot options for the host.
Security Issue references:
 * CVE-2012-0217
>
 * CVE-2012-0218
>
 * CVE-2012-2934
>Special Instructions and Notes:
Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Server 10-SP2, SUSE Linux Enterprise Server 10-SP3, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP1.");

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

if(release == "SLES10.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.0_16718_26_2.6.16.60_0.42.54.11~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.0_16718_26_2.6.16.60_0.42.54.11~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.0_16718_26_2.6.16.60_0.42.54.11~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.0_16718_26_2.6.16.60_0.42.54.11~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.0_16718_26_2.6.16.60_0.42.54.11~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.0_16718_26~0.8.1", rls:"SLES10.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdumppae", rpm:"xen-kmp-kdumppae~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmi", rpm:"xen-kmp-vmi~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmipae", rpm:"xen-kmp-vmipae~3.2.3_17040_28_2.6.16.60_0.83.131~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.3_17040_28~0.6.11.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-ps", rpm:"xen-doc-ps~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-bigsmp", rpm:"xen-kmp-bigsmp~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-debug", rpm:"xen-kmp-debug~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdump", rpm:"xen-kmp-kdump~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-kdumppae", rpm:"xen-kmp-kdumppae~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-smp", rpm:"xen-kmp-smp~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmi", rpm:"xen-kmp-vmi~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-vmipae", rpm:"xen-kmp-vmipae~3.2.3_17040_38_2.6.16.60_0.97.1~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-ioemu", rpm:"xen-tools-ioemu~3.2.3_17040_38~0.11.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_04_2.6.32.59_0.5~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_04_2.6.32.59_0.5~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_04_2.6.32.59_0.5~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_04~0.9.1", rls:"SLES11.0SP1"))) {
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
