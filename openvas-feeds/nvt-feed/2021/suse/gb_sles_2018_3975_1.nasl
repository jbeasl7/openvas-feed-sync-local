# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3975.1");
  script_cve_id("CVE-2018-10839", "CVE-2018-15746", "CVE-2018-17958", "CVE-2018-17962", "CVE-2018-17963", "CVE-2018-18438", "CVE-2018-18849");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:33 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-24 03:55:35 +0000 (Sat, 24 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3975-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3975-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183975-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114422");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2018:3975-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kvm fixes the following issues:

Security issues fixed:

- CVE-2018-10839: Fixed NE2000 NIC emulation support that is vulnerable to an integer overflow, which could lead to buffer overflow issue. It could occur when receiving packets over the network. A user inside guest could use this flaw to crash the Qemu process resulting in DoS (bsc#1110910).
- CVE-2018-15746: Fixed qemu-seccomp.c that might allow local OS guest users to cause a denial of service (guest crash) by leveraging mishandling of the seccomp policy for threads other than the main thread (bsc#1106222).
- CVE-2018-17958: Fixed a Buffer Overflow in rtl8139_do_receive in hw/net/rtl8139.c because an incorrect integer data type is used (bsc#1111006).
- CVE-2018-17962: Fixed a Buffer Overflow in pcnet_receive in hw/net/pcnet.c because an incorrect integer data type is used (bsc#1111010).
- CVE-2018-17963: Fixed qemu_deliver_packet_iov in net/net.c that accepts packet sizes greater than INT_MAX, which allows attackers to cause a denial of service or possibly have unspecified other impact. (bsc#1111013)
- CVE-2018-18849: Fixed an out of bounds memory access issue that was found in the LSI53C895A SCSI Host Bus Adapter emulation while writing a message in lsi_do_msgin. It could occur during migration if the 'msg_len' field has an invalid value. A user/process could use this flaw to crash the Qemu process resulting in DoS (bsc#1114422).
- CVE-2018-18438: Fixed integer overflows because IOReadHandler and its associated functions use a signed integer data type for a size value (bnc#1112185).");

  script_tag(name:"affected", value:"'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~1.4.2~60.18.2", rls:"SLES11.0SP4"))) {
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
