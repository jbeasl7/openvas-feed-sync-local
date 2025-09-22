# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1255.1");
  script_cve_id("CVE-2017-18255", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-21008", "CVE-2019-11091", "CVE-2019-14615", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-15213", "CVE-2019-18660", "CVE-2019-18675", "CVE-2019-18683", "CVE-2019-19052", "CVE-2019-19062", "CVE-2019-19066", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19319", "CVE-2019-19332", "CVE-2019-19447", "CVE-2019-19523", "CVE-2019-19524", "CVE-2019-19525", "CVE-2019-19527", "CVE-2019-19530", "CVE-2019-19531", "CVE-2019-19532", "CVE-2019-19533", "CVE-2019-19534", "CVE-2019-19535", "CVE-2019-19536", "CVE-2019-19537", "CVE-2019-19767", "CVE-2019-19768", "CVE-2019-19965", "CVE-2019-19966", "CVE-2019-20054", "CVE-2019-20096", "CVE-2019-3701", "CVE-2019-5108", "CVE-2019-9455", "CVE-2019-9458", "CVE-2020-10690", "CVE-2020-10720", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-2732", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-8992", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 14:55:37 +0000 (Tue, 10 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1255-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1255-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201255-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1037216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1159912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1167629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170778");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-May/006812.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1255-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-11494: An issue was discovered in slc_bump in drivers/net/can/slcan.c, which allowed attackers to read uninitialized can_frame data, potentially containing sensitive information from kernel stack memory, if the configuration lacks CONFIG_INIT_STACK_ALL (bnc#1168424).
- CVE-2020-10942: In get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family field, which might allow attackers to trigger kernel stack corruption via crafted system calls (bnc#1167629).
- CVE-2020-8647: Fixed a use-after-free vulnerability in the vc_do_resize function in drivers/tty/vt/vt.c (bnc#1162929).
- CVE-2020-8649: Fixed a use-after-free vulnerability in the vgacon_invert_region function in drivers/video/console/vgacon.c (bnc#1162931).
- CVE-2020-9383: Fixed an issue in set_fdc in drivers/block/floppy.c, which leads to a wait_til_ready out-of-bounds read (bnc#1165111).
- CVE-2019-9458: In the video driver there was a use after free due to a race condition. This could lead to local escalation of privilege with no additional execution privileges needed (bnc#1168295).
- CVE-2019-3701: Fixed an issue in can_can_gw_rcv, which could cause a system crash (bnc#1120386).
- CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function in kernel/trace/blktrace.c (bnc#1159285).
- CVE-2020-11609: Fixed a NULL pointer dereference in the stv06xx subsystem caused by mishandling invalid descriptors (bnc#1168854).
- CVE-2020-10720: Fixed a use-after-free read in napi_gro_frags() (bsc#1170778).
- CVE-2020-10690: Fixed the race between the release of ptp_clock and cdev (bsc#1170056).
- CVE-2019-9455: Fixed a pointer leak due to a WARN_ON statement in a video driver. This could lead to local information disclosure with System execution privileges needed (bnc#1170345).
- CVE-2020-11608: Fixed an issue in drivers/media/usb/gspca/ov519.c caused by a NULL pointer dereferences in ov511_mode_init_regs and ov518_mode_init_regs when there are zero endpoints (bnc#1168829).
- CVE-2017-18255: The perf_cpu_time_max_percent_handler function in kernel/events/core.c allowed local users to cause a denial of service (integer overflow) or possibly have unspecified other impact via a large value, as demonstrated by an incorrect sample-rate calculation (bnc#1087813).
- CVE-2020-8648: There was a use-after-free vulnerability in the n_tty_receive_buf_common function in drivers/tty/n_tty.c (bnc#1162928).
- CVE-2020-2732: A flaw was discovered in the way that the KVM hypervisor handled instruction emulation for an L2 guest when nested virtualisation is enabled. Under some circumstances, an L2 guest may trick the L0 guest into accessing sensitive L1 resources that should be inaccessible to the L2 guest (bnc#1163971).
- CVE-2019-5108: Fixed a denial-of-service vulnerability ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.129.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-4_4_121-92_129-default", rpm:"kgraft-patch-4_4_121-92_129-default~1~3.3.1", rls:"SLES12.0SP2"))) {
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
