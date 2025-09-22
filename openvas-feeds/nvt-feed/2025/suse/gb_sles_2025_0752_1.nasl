# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0752.1");
  script_cve_id("CVE-2023-45229", "CVE-2023-45230", "CVE-2023-45231", "CVE-2023-45232", "CVE-2023-45233", "CVE-2023-45234", "CVE-2023-45235");
  script_tag(name:"creation_date", value:"2025-03-03 04:08:07 +0000 (Mon, 03 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 15:58:27 +0000 (Tue, 23 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0752-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0752-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250752-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218885");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020464.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ovmf' package(s) announced via the SUSE-SU-2025:0752-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ovmf fixes the following issues:

- CVE-2023-45229: out-of-bounds read in edk2 when processing IA_NA/IA_TA options in DHCPv6 Advertise messages.
 (bsc#1218879)
- CVE-2023-45230: buffer overflow in the DHCPv6 client in edk2 via a long Server ID option. (bsc#1218880)
- CVE-2023-45231: out-of-bounds read in edk2 when handling a ND Redirect message with truncated options. (bsc#1218881)
- CVE-2023-45232: infinite loop in edk2 when parsing unknown options in the Destination Options header. (bsc#1218882)
- CVE-2023-45233: infinite loop in edk2 when parsing PadN options in the Destination Options header. (bsc#1218883)
- CVE-2023-45234: buffer overflow in edk2 when processing DNS Servers options in a DHCPv6 Advertise message.
 (bsc#1218884)
- CVE-2023-45235: buffer overflow in edk2 when handling the Server ID option in a DHCPv6 proxy Advertise message.
 (bsc#1218885)");

  script_tag(name:"affected", value:"'ovmf' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ovmf", rpm:"ovmf~202008~150300.10.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ovmf-tools", rpm:"ovmf-tools~202008~150300.10.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ovmf-x86_64", rpm:"qemu-ovmf-x86_64~202008~150300.10.26.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-uefi-aarch64", rpm:"qemu-uefi-aarch64~202008~150300.10.26.1", rls:"SLES15.0SP3"))) {
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
