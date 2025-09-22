# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.2847.1");
  script_cve_id("CVE-2017-1000252", "CVE-2017-11472", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-14489", "CVE-2017-15265", "CVE-2017-15649");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 14:04:04 +0000 (Tue, 29 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:2847-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:2847-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20172847-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1015343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1032150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1036737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1049580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981309");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-October/003353.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2847-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.92 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-1000252: The KVM subsystem in the Linux kernel allowed guest OS users to cause a denial of service (assertion failure, and hypervisor hang or crash) via an out-of bounds guest_irq value, related to arch/x86/kvm/vmx.c and virt/kvm/eventfd.c (bnc#1058038).
- CVE-2017-11472: The acpi_ns_terminate() function in drivers/acpi/acpica/nsutils.c in the Linux kernel did not flush the operand cache and causes a kernel stack dump, which allowed local users to obtain sensitive information from kernel memory and bypass the KASLR protection mechanism (in the kernel through 4.9) via a crafted ACPI table (bnc#1049580).
- CVE-2017-12134: The xen_biovec_phys_mergeable function in drivers/xen/biomerge.c in Xen might allow local OS guest users to corrupt block device data streams and consequently obtain sensitive memory information, cause a denial of service, or gain host OS privileges by leveraging incorrect block IO merge-ability calculation (bnc#1051790 bsc#1053919).
- CVE-2017-12153: A security flaw was discovered in the nl80211_set_rekey_data() function in net/wireless/nl80211.c in the Linux kernel This function did not check whether the required attributes are present in a Netlink request. This request can be issued by a user with the CAP_NET_ADMIN capability and may result in a NULL pointer dereference and system crash (bnc#1058410).
- CVE-2017-12154: The prepare_vmcs02 function in arch/x86/kvm/vmx.c in the Linux kernel did not ensure that the 'CR8-load exiting' and 'CR8-store exiting' L0 vmcs02 controls exist in cases where L1 omits the 'use TPR shadow' vmcs12 control, which allowed KVM L2 guest OS users to obtain read and write access to the hardware CR8 register (bnc#1058507).
- CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2) allowed reinstallation of the Group Temporal Key (GTK) during the group key handshake, allowing an attacker within radio range to replay frames from access points to clients (bnc#1056061 1063479 1063667 1063671).
- CVE-2017-14051: An integer overflow in the qla2x00_sysfs_write_optrom_ctl function in drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel allowed local users to cause a denial of service (memory corruption and system crash) by leveraging root access (bnc#1056588).
- CVE-2017-14106: The tcp_disconnect function in net/ipv4/tcp.c in the Linux kernel allowed local users to cause a denial of service (__tcp_select_window divide-by-zero error and system crash) by triggering a disconnect within a certain tcp_recvmsg code path (bnc#1056982).
- CVE-2017-14489: The iscsi_if_rx function in drivers/scsi/scsi_transport_iscsi.c in the Linux kernel allowed local users to cause a denial of service (panic) by leveraging incorrect length validation (bnc#1059051).
- CVE-2017-15265: Use-after-free ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.92~6.18.1", rls:"SLES12.0SP3"))) {
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
