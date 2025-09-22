# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3490.1");
  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-17963", "CVE-2018-3646");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3490-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3490-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183490-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111014");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004800.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2018:3490-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

XEN was updated to the Xen 4.9.3 bug fix only release (bsc#1027519)

- CVE-2018-17963: qemu_deliver_packet_iov accepted packet sizes greater than INT_MAX, which allows attackers to cause a denial of service or possibly have unspecified other impact. (bsc#1111014)
- CVE-2018-15470: oxenstored might not have enforced the configured quota-maxentity. This allowed a malicious or buggy guest to write as many xenstore entries as it wishes, causing unbounded memory usage in oxenstored. This can lead to a system-wide DoS. (XSA-272) (bsc#1103279)
- CVE-2018-15469: ARM never properly implemented grant table v2, either in the hypervisor or in Linux. Unfortunately, an ARM guest can still request v2 grant tables, they will simply not be properly set up, resulting in subsequent grant-related hypercalls hitting BUG() checks. An unprivileged guest can cause a BUG() check in the hypervisor, resulting in a denial-of-service (crash). (XSA-268) (bsc#1103275)
 Note that SUSE does not ship ARM Xen, so we are not affected.
- CVE-2018-15468: The DEBUGCTL MSR contains several debugging features, some of which virtualise cleanly, but some do not. In particular, Branch Trace Store is not virtualised by the processor, and software has to be careful to configure it suitably not to lock up the core. As a result, it must only be available to fully trusted guests. Unfortunately, in the case that vPMU is disabled, all value checking was skipped, allowing the guest to choose any MSR_DEBUGCTL setting it likes. A malicious or buggy guest administrator (on Intel x86 HVM or PVH) can lock up the entire host, causing a Denial of Service. (XSA-269) (bsc#1103276)
- CVE-2018-3646: Systems with microprocessors utilizing speculative execution and address translations may have allowed unauthorized disclosure of information residing in the L1 data cache to an attacker with local user access with guest OS privilege via a terminal page fault and a side-channel analysis. (XSA-273) (bsc#1091107)

Non security issues fixed:

- The affinity reporting via 'xl vcpu-list' was broken (bsc#1106263)
- Kernel oops in fs/dcache.c called by d_materialise_unique() (bsc#1094508)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.9.3_03~3.44.2", rls:"SLES12.0SP3"))) {
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
