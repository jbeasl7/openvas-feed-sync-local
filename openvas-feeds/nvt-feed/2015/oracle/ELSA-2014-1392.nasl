# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123272");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-2596", "CVE-2013-4483", "CVE-2014-0181", "CVE-2014-3122", "CVE-2014-3601", "CVE-2014-4608", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-5045", "CVE-2014-5077");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:35 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-28 14:01:45 +0000 (Fri, 28 Jun 2024)");

  script_name("Oracle: Security Advisory (ELSA-2014-1392)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1392");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1392.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-1392 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-504]
- [netdrv] revert 'cxgb4: set skb->rxhash' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Use netif_set_real_num_rx/tx_queues()' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Turn on delayed ACK' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Use ULP_MODE_TCPDDP' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Debugfs dump_qp() updates' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Drop peer_abort when no endpoint found' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Detect DB FULL events and notify RDMA ULD' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Common platform specific changes for DB Drop Recovery' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: DB Drop Recovery for RDMA and LLD queues' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Add debugfs RDMA memory stats' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Add DB Overflow Avoidance' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: DB Drop Recovery for RDMA and LLD queues' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Use vmalloc() for debugfs QP dump' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Remove kfifo usage' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Include vmalloc.h for vmalloc and vfree' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: set maximal number of default RSS queues' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Remove duplicate register definitions' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Update RDMA/cxgb4 due to macro definition removal in cxgb4 driver' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Move dereference below NULL test' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Fix incorrect values for MEMWIN*_APERTURE and MEMWIN*_BASE' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Add functions to read memory via PCIE memory window' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Code cleanup to enable T4 Configuration File support' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Add support for T4 configuration file' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Add support for T4 hardwired driver configuration settings' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Don't attempt to upgrade T4 firmware when cxgb4 will end up as a slave' (Prarit Bhargava) [1140743]
- [infiniband] revert 'cxgb4: Fix error handling in create_qp()' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Dynamically allocate memory in t4_memory_rw() and get_vpd_params()' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Fix build error due to missing linux/vmalloc.h include' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: allocate enough data in t4_memory_rw()' (Prarit Bhargava) [1140743]
- [netdrv] revert 'cxgb4: Address various sparse warnings' (Prarit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.el6", rls:"OracleLinux6"))) {
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
