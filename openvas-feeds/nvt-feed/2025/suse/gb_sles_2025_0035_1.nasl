# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0035.1");
  script_cve_id("CVE-2021-47162", "CVE-2022-48853", "CVE-2024-26801", "CVE-2024-26852", "CVE-2024-26886", "CVE-2024-27051", "CVE-2024-35937", "CVE-2024-36886", "CVE-2024-36905", "CVE-2024-36954", "CVE-2024-42098", "CVE-2024-42131", "CVE-2024-42229", "CVE-2024-44995", "CVE-2024-45016", "CVE-2024-46771", "CVE-2024-46777", "CVE-2024-46800", "CVE-2024-47660", "CVE-2024-47679", "CVE-2024-47701", "CVE-2024-49858", "CVE-2024-49868", "CVE-2024-49884", "CVE-2024-49921", "CVE-2024-49925", "CVE-2024-49938", "CVE-2024-49945", "CVE-2024-49950", "CVE-2024-49952", "CVE-2024-50044", "CVE-2024-50055", "CVE-2024-50073", "CVE-2024-50074", "CVE-2024-50095", "CVE-2024-50099", "CVE-2024-50115", "CVE-2024-50117", "CVE-2024-50125", "CVE-2024-50135", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50154", "CVE-2024-50167", "CVE-2024-50171", "CVE-2024-50179", "CVE-2024-50183", "CVE-2024-50187", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50210", "CVE-2024-50218", "CVE-2024-50234", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50264", "CVE-2024-50265", "CVE-2024-50267", "CVE-2024-50273", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50289", "CVE-2024-50290", "CVE-2024-50296", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53058", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53085", "CVE-2024-53088", "CVE-2024-53104", "CVE-2024-53114", "CVE-2024-53142");
  script_tag(name:"creation_date", value:"2025-01-09 04:17:27 +0000 (Thu, 09 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 19:17:56 +0000 (Tue, 10 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0035-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250035-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234087");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020070.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-48853: swiotlb: fix info leak with DMA_FROM_DEVICE (bsc#1228015).
- CVE-2024-26801: Bluetooth: Avoid potential use-after-free in hci_error_reset (bsc#1222413).
- CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify() (bsc#1223057).
- CVE-2024-26886: Bluetooth: af_bluetooth: Fix deadlock (bsc#1223044).
- CVE-2024-27051: cpufreq: brcmstb-avs-cpufreq: add check for cpufreq_cpu_get's return value (bsc#1223769).
- CVE-2024-35937: wifi: cfg80211: check A-MSDU format more carefully (bsc#1224526).
- CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (bsc#1225742).
- CVE-2024-42098: crypto: ecdh - explicitly zeroize private_key (bsc#1228779).
- CVE-2024-42229: crypto: aead,cipher - zeroize key buffer after use (bsc#1228708).
- CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during resetting (bsc#1230231).
- CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
- CVE-2024-46771: can: bcm: Remove proc entry when dev is unregistered (bsc#1230766).
- CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
- CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
- CVE-2024-47660: fsnotify: clear PARENT_WATCHED flags lazily (bsc#1231439).
- CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode()&iput() (bsc#1231930).
- CVE-2024-47701: ext4: avoid OOB when system.data xattr changes underneath the filesystem (bsc#1231920).
- CVE-2024-49858: efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption (bsc#1232251).
- CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a new trasacntion (bsc#1232272).
- CVE-2024-49921: drm/amd/display: Check null pointers before used (bsc#1232371).
- CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
- CVE-2024-49938: wifi: ath9k_htc: Use __skb_set_length() for resetting urb before resubmit (bsc#1232552).
- CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
- CVE-2024-49950: Bluetooth: L2CAP: Fix uaf in l2cap_connect (bsc#1232159).
- CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
- CVE-2024-50044: Bluetooth: RFCOMM: FIX possible deadlock in rfcomm_sk_state_change (bsc#1231904).
- CVE-2024-50055: driver core: bus: Fix double free in driver API bus_register() (bsc#1232329).
- CVE-2024-50073: tty: n_gsm: Fix use-after-free in gsm_cleanup_mux (bsc#1232520).
- CVE-2024-50074: parport: Proper fix for array out-of-bounds access (bsc#1232507).
- CVE-2024-50095: RDMA/mad: Improve handling of timed out WRs of mad agent (bsc#1232873).
- CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.237.1", rls:"SLES12.0SP5"))) {
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
