# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0785.1");
  script_cve_id("CVE-2017-13166", "CVE-2017-15951", "CVE-2017-16644", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-17975", "CVE-2017-18208", "CVE-2018-1000026", "CVE-2018-1068", "CVE-2018-8087");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-10 15:19:19 +0000 (Tue, 10 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0785-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0785-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180785-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1034503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1035432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983145");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-March/003835.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0785-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.120 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-13166: An elevation of privilege vulnerability in the v4l2 video driver was fixed. (bnc#1072865).
- CVE-2017-15951: The KEYS subsystem did not correctly synchronize the actions of updating versus finding a key in the 'negative' state to avoid a race condition, which allowed local users to cause a denial of service or possibly have unspecified other impact via crafted system calls (bnc#1062840 bnc#1065615).
- CVE-2017-16644: The hdpvr_probe function in drivers/media/usb/hdpvr/hdpvr-core.c allowed local users to cause a denial of service (improper error handling and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1067118).
- CVE-2017-16912: The 'get_pipe()' function (drivers/usb/usbip/stub_rx.c) allowed attackers to cause a denial of service (out-of-bounds read) via a specially crafted USB over IP packet (bnc#1078673).
- CVE-2017-16913: The 'stub_recv_cmd_submit()' function (drivers/usb/usbip/stub_rx.c) when handling CMD_SUBMIT packets allowed attackers to cause a denial of service (arbitrary memory allocation) via a specially crafted USB over IP packet (bnc#1078672).
- CVE-2017-17975: Use-after-free in the usbtv_probe function in drivers/media/usb/usbtv/usbtv-core.c allowed attackers to cause a denial of service (system crash) or possibly have unspecified other impact by triggering failure of audio registration, because a kfree of the usbtv data structure occurs during a usbtv_video_free call, but the usbtv_video_fail label's code attempts to both access and free this data structure (bnc#1074426).
- CVE-2017-18208: The madvise_willneed function in mm/madvise.c allowed local users to cause a denial of service (infinite loop) by triggering use of MADVISE_WILLNEED for a DAX mapping (bnc#1083494).
- CVE-2018-8087: Memory leak in the hwsim_new_radio_nl function in drivers/net/wireless/mac80211_hwsim.c allowed local users to cause a denial of service (memory consumption) by triggering an out-of-array error case (bnc#1085053).
- CVE-2018-1000026: A insufficient input validation vulnerability in the bnx2x network card driver could result in DoS: Network card firmware assertion takes card off-line. This attack appear to be exploitable via An attacker on a must pass a very large, specially crafted packet to the bnx2x card. This can be done from an untrusted guest VM. (bnc#1079384).
- CVE-2018-1068: Insufficient user provided offset checking in the ebtables compat code allowed local attackers to overwrite kernel memory and potentially execute code. (bsc#1085107)

The following non-security bugs were fixed:

- acpi / bus: Leave modalias empty for devices which are not present (bnc#1012382).
- acpi: sbshc: remove raw pointer from printk() message (bnc#1012382).
- Add delay-init quirk for ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.120~92.70.1", rls:"SLES12.0SP2"))) {
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
