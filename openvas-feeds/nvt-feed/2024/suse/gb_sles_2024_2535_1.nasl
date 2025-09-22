# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2535.1");
  script_cve_id("CVE-2023-28746", "CVE-2023-46842", "CVE-2024-2193", "CVE-2024-2201", "CVE-2024-31142", "CVE-2024-31143");
  script_tag(name:"creation_date", value:"2024-07-17 04:24:45 +0000 (Wed, 17 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2535-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2535-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242535-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227355");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018986.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2024:2535-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

- CVE-2023-28746: Register File Data Sampling (XSA-452, bsc#1221332)
- CVE-2023-46842: HVM hypercalls may trigger Xen bug check (XSA-454, bsc#1221984)
- CVE-2024-2193: Fixed GhostRace, a speculative race conditions. (XSA-453, bsc#1221334)
- CVE-2024-2201: Mitigation for Native Branch History Injection (XSA-456, bsc#1222453)
- CVE-2024-31142: Fixed incorrect logic for BTC/SRSO mitigations (XSA-455, bsc#1222302)
- CVE-2024-31143: Fixed double unlock in x86 guest IRQ handling (XSA-458, bsc#1227355)");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-xendomains-wait-disk", rpm:"xen-tools-xendomains-wait-disk~4.13.5_12~150200.3.93.1", rls:"SLES15.0SP2"))) {
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
