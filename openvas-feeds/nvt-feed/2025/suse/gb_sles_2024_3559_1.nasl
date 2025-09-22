# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3559.1");
  script_cve_id("CVE-2021-47387", "CVE-2022-48788", "CVE-2022-48789", "CVE-2022-48790", "CVE-2022-48791", "CVE-2022-48799", "CVE-2022-48844", "CVE-2022-48911", "CVE-2022-48943", "CVE-2022-48945", "CVE-2023-52915", "CVE-2024-38381", "CVE-2024-38596", "CVE-2024-38632", "CVE-2024-41073", "CVE-2024-41079", "CVE-2024-41082", "CVE-2024-42154", "CVE-2024-42265", "CVE-2024-42305", "CVE-2024-42306", "CVE-2024-43884", "CVE-2024-43890", "CVE-2024-43898", "CVE-2024-43912", "CVE-2024-43914", "CVE-2024-44946", "CVE-2024-44947", "CVE-2024-44948", "CVE-2024-44950", "CVE-2024-44952", "CVE-2024-44954", "CVE-2024-44969", "CVE-2024-44982", "CVE-2024-44987", "CVE-2024-44998", "CVE-2024-44999", "CVE-2024-45008", "CVE-2024-46673", "CVE-2024-46675", "CVE-2024-46676", "CVE-2024-46677", "CVE-2024-46679", "CVE-2024-46685", "CVE-2024-46686", "CVE-2024-46702", "CVE-2024-46707", "CVE-2024-46715", "CVE-2024-46721", "CVE-2024-46722", "CVE-2024-46723", "CVE-2024-46731", "CVE-2024-46737", "CVE-2024-46738", "CVE-2024-46739", "CVE-2024-46743", "CVE-2024-46744", "CVE-2024-46745", "CVE-2024-46750", "CVE-2024-46753", "CVE-2024-46759", "CVE-2024-46761", "CVE-2024-46770", "CVE-2024-46774", "CVE-2024-46783", "CVE-2024-46784", "CVE-2024-46787", "CVE-2024-46822", "CVE-2024-46853", "CVE-2024-46854", "CVE-2024-46859");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-03 16:47:24 +0000 (Thu, 03 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3559-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243559-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231184");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037179.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:3559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47387: cpufreq: schedutil: Destroy mutex before kobject_put() frees the memory (bsc#1225316).
- CVE-2022-48788: nvme-rdma: fix possible use-after-free in transport error_recovery work (bsc#1227952).
- CVE-2022-48789: nvme-tcp: fix possible use-after-free in transport error_recovery work (bsc#1228000).
- CVE-2022-48790: nvme: fix a possible use-after-free in controller reset during load (bsc#1227941).
- CVE-2022-48791: Fix use-after-free for aborted TMF sas_task (bsc#1228002)
- CVE-2022-48799: perf: Fix list corruption in perf_cgroup_switch() (bsc#1227953).
- CVE-2022-48844: Bluetooth: hci_core: Fix leaking sent_cmd skb (bsc#1228068).
- CVE-2022-48911: kabi: add __nf_queue_get_refs() for kabi compliance. (bsc#1229633).
- CVE-2022-48943: KVM: x86/mmu: make apf token non-zero to fix bug (bsc#1229645).
- CVE-2022-48945: media: vivid: fix compose size exceed boundary (bsc#1230398).
- CVE-2023-52915: media: dvb-usb-v2: af9035: fix missing unlock (bsc#1230270).
- CVE-2024-38596: af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg (bsc#1226846).
- CVE-2024-41073: nvme: avoid double free special payload (bsc#1228635).
- CVE-2024-41079: nvmet: always initialize cqe.result (bsc#1228615).
- CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command (bsc#1228620 CVE-2024-41082).
- CVE-2024-42154: tcp_metrics: validate source addr length (bsc#1228507).
- CVE-2024-42265: protect the fetch of ->fd[fd] in do_dup2() from mispredictions (bsc#1229334).
- CVE-2024-42305: ext4: check dot and dotdot of dx_root before making dir indexed (bsc#1229363).
- CVE-2024-42306: udf: Avoid using corrupted block bitmap buffer (bsc#1229362).
- CVE-2024-43884: Add error handling to pair_device() (bsc#1229739)
- CVE-2024-43890: tracing: Fix overflow in get_free_elt() (bsc#1229764).
- CVE-2024-43898: ext4: sanity check for NULL pointer after ext4_force_shutdown (bsc#1229753).
- CVE-2024-43912: wifi: nl80211: disallow setting special AP channel widths (bsc#1229830)
- CVE-2024-43914: md/raid5: avoid BUG_ON() while continue reshape after reassembling (bsc#1229790).
- CVE-2024-44946: kcm: Serialise kcm_sendmsg() for the same socket (bsc#1230015).
- CVE-2024-44948: x86/mtrr: Check if fixed MTRRs exist before saving them (bsc#1230174).
- CVE-2024-44950: serial: sc16is7xx: fix invalid FIFO access with special register set (bsc#1230180).
- CVE-2024-44952: driver core: Fix uevent_show() vs driver detach race (bsc#1230178).
- CVE-2024-44954: ALSA: line6: Fix racy access to midibuf (bsc#1230176).
- CVE-2024-44969: s390/sclp: Prevent release of buffer in I/O (bsc#1230200).
- CVE-2024-44982: drm/msm/dpu: cleanup FB if dpu_format_populate_layout fails (bsc#1230204).
- CVE-2024-44987: ipv6: prevent UAF in ip6_send_skb() (bsc#1230185).
- CVE-2024-44998: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.231.1", rls:"SLES12.0SP5"))) {
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
