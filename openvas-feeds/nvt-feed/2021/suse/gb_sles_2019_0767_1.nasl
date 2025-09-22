# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0767.1");
  script_cve_id("CVE-2018-20669", "CVE-2019-2024", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0767-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0767-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190767-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828192");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-March/005245.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0767-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise Server 12 SP4 Azure kernel was updated to fix various issues.

The following security bugs were fixed:

- CVE-2019-2024: A use-after-free when disconnecting a source was fixed which could lead to crashes. bnc#1129179).
- CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap minimum address, which made it easier for attackers to exploit kernel NULL pointer dereferences on non-SMAP platforms. This is related to a capability check for the wrong task (bnc#1128166 1128378 1129016).
- CVE-2019-8980: A memory leak in the kernel_read_file function in fs/exec.c allowed attackers to cause a denial of service (memory consumption) by triggering vfs_read failures (bnc#1126209).
- CVE-2019-3819: A flaw was found in the function hid_debug_events_read() in drivers/hid/hid-debug.c file which may enter an infinite loop with certain parameters passed from a userspace. A local privileged user ('root') can cause a system lock up and a denial of service. (bnc#1123161).
- CVE-2019-8912: af_alg_release() in crypto/af_alg.c neglected to set a NULL value for a certain structure member, which led to a use-after-free in sockfs_setattr (bnc#1125907 1126284).
- CVE-2019-7308: kernel/bpf/verifier.c performed undesirable out-of-bounds speculation on pointer arithmetic in various cases, including cases of different branches with different state or limits to sanitize, leading to side-channel attacks (bnc#1124055).
- CVE-2019-3459, CVE-2019-3460: The Bluetooth stack suffered from two remote information leak vulnerabilities in the code that handles incoming L2cap configuration packets (bsc#1120758).
- CVE-2019-7221: Fixed a use-after-free vulnerability in the KVM hypervisor related to the emulation of a preemption timer, allowing an guest user/process to crash the host kernel. (bsc#1124732).
- CVE-2019-7222: Fixed an information leakage in the KVM hypervisor related to handling page fault exceptions, which allowed a guest user/process to use this flaw to leak the host's stack memory contents to a guest (bsc#1124735).
- CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled reference counting because of a race condition, leading to a use-after-free (bnc#1124728).
- CVE-2018-20669: An issue where a provided address with access_ok() is not checked was discovered in i915_gem_execbuffer2_ioctl in drivers/gpu/drm/i915/i915_gem_execbuffer.c where a local attacker can craft a malicious IOCTL function call to overwrite arbitrary kernel memory, resulting in a Denial of Service or privilege escalation (bnc#1122971).

The following non-security bugs were fixed:

- 6lowpan: iphc: reset mac_header after decompress to fix panic (bsc#1051510).
- 9p: clear dangling pointers in p9stat_free (bsc#1051510).
- 9p locks: fix glock.client_id leak in do_lock (bsc#1051510).
- 9p/net: fix memory leak in p9_client_create (bsc#1051510).
- 9p/net: put a lower bound on msize ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.9.1", rls:"SLES12.0SP4"))) {
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
