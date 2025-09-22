# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1851.1");
  script_cve_id("CVE-2018-16871", "CVE-2018-20836", "CVE-2019-10126", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-11478", "CVE-2019-11599", "CVE-2019-12456", "CVE-2019-12614", "CVE-2019-12818", "CVE-2019-12819");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-17 14:11:17 +0000 (Mon, 17 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1851-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1851-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191851-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/945811");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1851-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2019-10638: A device could have been tracked by an attacker using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and ICMP). When such traffic was sent to multiple destination IP addresses, it was possible to obtain hash collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). An attack may have been conducted by hosting a crafted web page that uses WebRTC or gQUIC to force UDP traffic to attacker-controlled IP addresses. (bnc#1140575)
- CVE-2019-10639: Information Exposure (partial kernel address disclosure), leading to a KASLR bypass. Specifically, it was possible to extract the KASLR kernel image offset using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and ICMP). When such traffic was sent to multiple destination IP addresses, it was possible to obtain hash collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). This key contains enough bits from a kernel address (of a static variable) so when the key is extracted (via enumeration), the offset of the kernel image was exposed. This attack could have been carried out remotely, by the attacker forcing the target device to send UDP or ICMP (or certain other) traffic to attacker-controlled IP addresses. Forcing a server to send UDP traffic is trivial if the server is a DNS server. ICMP traffic was trivial if the server answered ICMP Echo requests (ping). For client targets, if the target visited the attacker's web page, then WebRTC or gQUIC could be used to force UDP traffic to attacker-controlled IP addresses. (bnc#1140577)
- CVE-2018-20836: A race condition in smp_task_timedout() and smp_task_done() in drivers/scsi/libsas/sas_expander.c, could have lead to a use-after-free. (bnc#1134395)
- CVE-2019-11599: The coredump implementation in the Linux kernel did not use locking or other mechanisms to prevent vma layout or vma flags changes while it runs, which allowed local users to obtain sensitive information, cause a denial of service, or possibly have unspecified other impact by triggering a race condition with mmget_not_zero or get_task_mm calls. This is related to fs/userfaultfd.c, mm/mmap.c, fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c. (bnc#1133738)
- CVE-2019-12614: An unchecked kstrdup might have allowed an attacker to cause denial of service (a NULL pointer dereference and system crash). (bnc#1137194)
- CVE-2019-12819: The function __mdiobus_register() in drivers/net/phy/mdio_bus.c called put_device() which would trigger a fixed_mdio_bus_init use-after-free. This would cause a denial of service. (bnc#1138291)
- CVE-2019-12818: The nfc_llcp_build_tlv function in net/nfc/llcp_commands.c may have returned NULL. If ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.24.1", rls:"SLES12.0SP4"))) {
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
