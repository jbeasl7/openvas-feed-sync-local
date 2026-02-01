# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0316.1");
  script_cve_id("CVE-2022-49546", "CVE-2022-49604", "CVE-2022-49975", "CVE-2022-50527", "CVE-2022-50615", "CVE-2022-50625", "CVE-2022-50630", "CVE-2022-50636", "CVE-2022-50638", "CVE-2022-50640", "CVE-2022-50643", "CVE-2022-50646", "CVE-2022-50656", "CVE-2022-50668", "CVE-2022-50677", "CVE-2022-50678", "CVE-2022-50700", "CVE-2022-50706", "CVE-2022-50715", "CVE-2022-50728", "CVE-2022-50730", "CVE-2022-50733", "CVE-2022-50747", "CVE-2022-50755", "CVE-2022-50761", "CVE-2022-50779", "CVE-2022-50821", "CVE-2022-50824", "CVE-2022-50840", "CVE-2022-50849", "CVE-2022-50850", "CVE-2022-50859", "CVE-2022-50870", "CVE-2022-50879", "CVE-2023-20569", "CVE-2023-23559", "CVE-2023-4132", "CVE-2023-53020", "CVE-2023-53176", "CVE-2023-53454", "CVE-2023-53718", "CVE-2023-53746", "CVE-2023-53748", "CVE-2023-53754", "CVE-2023-53765", "CVE-2023-53781", "CVE-2023-53786", "CVE-2023-53788", "CVE-2023-53803", "CVE-2023-53809", "CVE-2023-53819", "CVE-2023-53832", "CVE-2023-53840", "CVE-2023-53847", "CVE-2023-53850", "CVE-2023-53862", "CVE-2023-54014", "CVE-2023-54017", "CVE-2023-54021", "CVE-2023-54032", "CVE-2023-54045", "CVE-2023-54051", "CVE-2023-54070", "CVE-2023-54091", "CVE-2023-54095", "CVE-2023-54108", "CVE-2023-54110", "CVE-2023-54119", "CVE-2023-54120", "CVE-2023-54123", "CVE-2023-54130", "CVE-2023-54146", "CVE-2023-54168", "CVE-2023-54170", "CVE-2023-54177", "CVE-2023-54179", "CVE-2023-54186", "CVE-2023-54197", "CVE-2023-54211", "CVE-2023-54213", "CVE-2023-54214", "CVE-2023-54220", "CVE-2023-54224", "CVE-2023-54226", "CVE-2023-54236", "CVE-2023-54260", "CVE-2023-54264", "CVE-2023-54266", "CVE-2023-54270", "CVE-2023-54271", "CVE-2023-54286", "CVE-2023-54289", "CVE-2023-54294", "CVE-2023-54300", "CVE-2023-54309", "CVE-2023-54317", "CVE-2025-38085", "CVE-2025-38336", "CVE-2025-38728", "CVE-2025-40006", "CVE-2025-40035", "CVE-2025-40053", "CVE-2025-40064", "CVE-2025-40074", "CVE-2025-40075", "CVE-2025-40081", "CVE-2025-40110", "CVE-2025-40123", "CVE-2025-40135", "CVE-2025-40139", "CVE-2025-40149", "CVE-2025-40153", "CVE-2025-40158", "CVE-2025-40160", "CVE-2025-40164", "CVE-2025-40167", "CVE-2025-40168", "CVE-2025-40170", "CVE-2025-40178", "CVE-2025-40198", "CVE-2025-40200", "CVE-2025-40215", "CVE-2025-40219", "CVE-2025-40233", "CVE-2025-40240", "CVE-2025-40244", "CVE-2025-40248", "CVE-2025-40252", "CVE-2025-40256", "CVE-2025-40269", "CVE-2025-40275", "CVE-2025-40278", "CVE-2025-40279", "CVE-2025-40283", "CVE-2025-40304", "CVE-2025-40308", "CVE-2025-40321", "CVE-2025-40322", "CVE-2025-40331", "CVE-2025-40337", "CVE-2025-40349", "CVE-2025-40351", "CVE-2025-68206", "CVE-2025-68340");
  script_tag(name:"creation_date", value:"2026-01-30 04:34:32 +0000 (Fri, 30 Jan 2026)");
  script_version("2026-01-30T05:55:24+0000");
  script_tag(name:"last_modification", value:"2026-01-30 05:55:24 +0000 (Fri, 30 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-16 21:21:16 +0000 (Fri, 16 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0316-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0316-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260316-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256684");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023970.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0316-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-49604,CVE-2025-40074: ip: Fix data-races around sysctl_ip_fwd_use_pmtu (bsc#1238414 bsc#1252794).
- CVE-2022-50527: drm/amdgpu: Fix size validation for non-exclusive domains (v4) (bsc#1251738).
- CVE-2022-50625: serial: amba-pl011: avoid SBSA UART accessing DMACR register (bsc#1254559).
- CVE-2022-50630: mm: hugetlb: fix UAF in hugetlb_handle_userfault (bsc#1254785).
- CVE-2022-50656: nfc: pn533: Clear nfc_target before being used (bsc#1254745).
- CVE-2022-50678: wifi: brcmfmac: fix invalid address access when enabling SCAN log level (bsc#1254902).
- CVE-2022-50700: wifi: ath10k: Delay the unmapping of the buffer (bsc#1255576).
- CVE-2023-53454: HID: multitouch: Correct devm device reference for hidinput input_dev name (bsc#1250759).
- CVE-2023-53718: ring-buffer: Do not swap cpu_buffer during resize process (bsc#1252564).
- CVE-2023-53748: media: mediatek: vcodec: Fix potential array out-of-bounds in decoder queue_setup (bsc#1254907).
- CVE-2023-53765: dm cache: free background tracker's queued work in btracker_destroy (bsc#1254912).
- CVE-2023-53781: smc: Fix use-after-free in tcp_write_timer_handler() (bsc#1254751).
- CVE-2023-53788: ALSA: hda/ca0132: fixup buffer overrun at tuning_ctl_set() (bsc#1254917).
- CVE-2023-53819: amdgpu: validate offset_in_bo of drm_amdgpu_gem_va (bsc#1254712).
- CVE-2023-53850: iavf: use internal state to free traffic IRQs (bsc#1254677).
- CVE-2023-54120: Bluetooth: Fix race condition in hidp_session_thread (bsc#1256133).
- CVE-2023-54214: Bluetooth: L2CAP: Fix potential user-after-free (bsc#1255954).
- CVE-2023-54236: net/net_failover: fix txq exceeding warning (bsc#1255922).
- CVE-2023-54286: wifi: iwlwifi: dvm: Fix memcpy: detected field-spanning write backtrace (bsc#1255803).
- CVE-2023-54300: wifi: ath9k: avoid referencing uninit memory in ath9k_wmi_ctrl_rx (bsc#1255790).
- CVE-2025-38085: mm/hugetlb: fix huge_pmd_unshare() vs GUP-fast race (bsc#1245431 bsc#1245499).
- CVE-2025-38336: ata: pata_via: Force PIO for ATAPI devices on VT6415/VT6330 (bsc#1246370).
- CVE-2025-38728: smb3: fix for slab out of bounds on mount to ksmbd (bsc#1249256).
- CVE-2025-40006: mm/hugetlb: fix folio is still mapped when deleted (bsc#1252342).
- CVE-2025-40035: Input: uinput - zero-initialize uinput_ff_upload_compat to avoid info leak (bsc#1252866).
- CVE-2025-40053: net: dlink: handle copy_thresh allocation failure (bsc#1252808).
- CVE-2025-40064: smc: Fix use-after-free in __pnet_find_base_ndev() (bsc#1252845).
- CVE-2025-40075: tcp_metrics: use dst_dev_net_rcu() (bsc#1252795).
- CVE-2025-40081: perf: arm_spe: Prevent overflow in PERF_IDX2OFF() (bsc#1252776).
- CVE-2025-40110: drm/vmwgfx: Fix a null-ptr access in the cursor snooper (bsc#1253275).
- CVE-2025-40123: bpf: Enforce expected_attach_type for tailcall ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.290.1", rls:"SLES12.0SP5"))) {
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
