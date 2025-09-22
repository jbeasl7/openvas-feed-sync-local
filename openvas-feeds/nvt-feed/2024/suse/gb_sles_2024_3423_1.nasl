# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3423.1");
  script_cve_id("CVE-2024-2201", "CVE-2024-31143", "CVE-2024-31145", "CVE-2024-31146", "CVE-2024-45817");
  script_tag(name:"creation_date", value:"2024-09-25 04:30:17 +0000 (Wed, 25 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3423-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3423-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243423-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230366");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-September/019508.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2024:3423-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2024-2201: Mitigation for Native Branch History Injection (XSA-456, bsc#1222453)
- CVE-2024-31143: Fixed double unlock in x86 guest IRQ handling (XSA-458, bsc#1227355)
- CVE-2024-31145: Fixed error handling in x86 IOMMU identity mapping (XSA-460, bsc#1228574)
- CVE-2024-31146: Fixed PCI device pass-through with shared resources (XSA-461, bsc#1228575)
- CVE-2024-45817: Fixed a deadlock in vlapic_error (XSA-462, bsc#1230366)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-xendomains-wait-disk", rpm:"xen-tools-xendomains-wait-disk~4.16.6_04~150400.4.62.1", rls:"SLES15.0SP4"))) {
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
