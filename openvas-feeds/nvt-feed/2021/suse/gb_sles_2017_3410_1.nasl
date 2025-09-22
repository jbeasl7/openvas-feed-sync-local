# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3410.1");
  script_cve_id("CVE-2017-1000410", "CVE-2017-11600", "CVE-2017-12193", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-16528", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16645", "CVE-2017-16646", "CVE-2017-16994", "CVE-2017-17448", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-7482", "CVE-2017-8824");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 17:06:31 +0000 (Thu, 21 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3410-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3410-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173410-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1028971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1030061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1053919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/964944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996376");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003550.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:3410-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.103 to receive various security and bugfixes.

This update enables SMB encryption in the CIFS support in the Linux Kernel (fate#324404)

The following security bugs were fixed:

- CVE-2017-1000410: The Linux kernel was affected by an information leak in the processing of incoming L2CAP commands - ConfigRequest, and ConfigResponse messages. (bnc#1070535).
- CVE-2017-11600: net/xfrm/xfrm_policy.c in the Linux kernel did not ensure that the dir value of xfrm_userpolicy_id is XFRM_POLICY_MAX or less, which allowed local users to cause a denial of service (out-of-bounds access) or possibly have unspecified other impact via an XFRM_MSG_MIGRATE xfrm Netlink message (bnc#1050231).
- CVE-2017-12193: The assoc_array_insert_into_terminal_node function in lib/assoc_array.c in the Linux kernel mishandled node splitting, which allowed local users to cause a denial of service (NULL pointer dereference and panic) via a crafted application, as demonstrated by the keyring key type, and key addition and link creation operations (bnc#1066192).
- CVE-2017-15115: The sctp_do_peeloff function in net/sctp/socket.c in the Linux kernel did not check whether the intended netns is used in a peel-off action, which allowed local users to cause a denial of service (use-after-free and system crash) or possibly have unspecified other impact via crafted system calls (bnc#1068671).
- CVE-2017-15265: Race condition in the ALSA subsystem in the Linux kernel allowed local users to cause a denial of service (use-after-free) or possibly have unspecified other impact via crafted /dev/snd/seq ioctl calls, related to sound/core/seq/seq_clientmgr.c and sound/core/seq/seq_ports.c (bnc#1062520).
- CVE-2017-16528: sound/core/seq_device.c in the Linux kernel allowed local users to cause a denial of service (snd_rawmidi_dev_seq_free use-after-free and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066629).
- CVE-2017-16536: The cx231xx_usb_probe function in drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066606).
- CVE-2017-16537: The imon_probe function in drivers/media/rc/imon.c in the Linux kernel allowed local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066573).
- CVE-2017-16645: The ims_pcu_get_cdc_union_desc function in drivers/input/misc/ims-pcu.c in the Linux kernel allowed local users to cause a denial of service (ims_pcu_parse_cdc_data out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1067132).
- CVE-2017-16646: drivers/media/usb/dvb-usb/dib0700_devices.c in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.103~92.53.1", rls:"SLES12.0SP2"))) {
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
