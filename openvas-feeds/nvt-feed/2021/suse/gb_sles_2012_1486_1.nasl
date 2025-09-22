# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1486.1");
  script_cve_id("CVE-2012-3497", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1486-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121486-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2012:1486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XEN was updated to fix various bugs and security issues:

The following security issues have been fixed:

 * CVE-2012-4544: xen: Domain builder Out-of-memory due to malicious kernel/ramdisk (XSA 25)
 * CVE-2012-4411: XEN / qemu: guest administrator can access qemu monitor console (XSA-19)
 * CVE-2012-4535: xen: Timer overflow DoS vulnerability
(XSA 20)
 * CVE-2012-4536: xen: pirq range check DoS vulnerability (XSA 21)
 * CVE-2012-4537: xen: Memory mapping failure DoS vulnerability (XSA 22)
 * CVE-2012-4538: xen: Unhooking empty PAE entries DoS vulnerability (XSA 23)
 * CVE-2012-4539: xen: Grant table hypercall infinite loop DoS vulnerability (XSA 24)
 * CVE-2012-3497: xen: multiple TMEM hypercall vulnerabilities (XSA-15)

Also the following bugs have been fixed and upstream patches have been applied:

 *

 bnc#784087 - L3: Xen BUG at io_apic.c:129 26102-x86-IOAPIC-legacy-not-first.patch

 *

 Upstream patches merged:
26054-x86-AMD-perf-ctr-init.patch 26055-x86-oprof-hvm-mode.patch 26056-page-alloc-flush-filter.patch 26061-x86-oprof-counter-range.patch 26062-ACPI-ERST-move-data.patch 26063-x86-HPET-affinity-lock.patch 26093-HVM-PoD-grant-mem-type.patch 25931-x86-domctl-iomem-mapping-checks.patch 25952-x86-MMIO-remap-permissions.patch 25808-domain_create-return-value.patch 25814-x86_64-set-debugreg-guest.patch 25815-x86-PoD-no-bug-in-non-translated.patch 25816-x86-hvm-map-pirq-range-check.patch 25833-32on64-bogus-pt_base-adjust.patch 25834-x86-S3-MSI-resume.patch 25835-adjust-rcu-lock-domain.patch 25836-VT-d-S3-MSI-resume.patch 25850-tmem-xsa-15-1.patch 25851-tmem-xsa-15-2.patch 25852-tmem-xsa-15-3.patch 25853-tmem-xsa-15-4.patch 25854-tmem-xsa-15-5.patch 25855-tmem-xsa-15-6.patch 25856-tmem-xsa-15-7.patch 25857-tmem-xsa-15-8.patch 25858-tmem-xsa-15-9.patch 25859-tmem-missing-break.patch 25860-tmem-cleanup.patch 25883-pt-MSI-cleanup.patch 25927-x86-domctl-ioport-mapping-range.patch 25929-tmem-restore-pool-version.patch

 *

 bnc#778105 - first XEN-PV VM fails to spawn xend:
Increase wait time for disk to appear in host bootloader Modified existing xen-domUloader.diff

 25752-ACPI-pm-op-valid-cpu.patch 25754-x86-PoD-early-access.patch 25755-x86-PoD-types.patch 25756-x86-MMIO-max-mapped-pfn.patch

Security Issue references:

 * CVE-2012-4539
>
 * CVE-2012-3497
>
 * CVE-2012-4411
>
 * CVE-2012-4535
>
 * CVE-2012-4537
>
 * CVE-2012-4536
>
 * CVE-2012-4538
>
 * CVE-2012-4539
>
 * CVE-2012-4544
>");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.3_04_3.0.42_0.7~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.3_04_3.0.42_0.7~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.1.3_04_3.0.42_0.7~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.3_04~0.5.1", rls:"SLES11.0SP2"))) {
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
