# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856115");
  script_cve_id("CVE-2021-46925", "CVE-2021-46926", "CVE-2021-46927", "CVE-2021-46929", "CVE-2021-46930", "CVE-2021-46931", "CVE-2021-46933", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-47082", "CVE-2021-47083", "CVE-2021-47087", "CVE-2021-47091", "CVE-2021-47093", "CVE-2021-47094", "CVE-2021-47095", "CVE-2021-47096", "CVE-2021-47097", "CVE-2021-47098", "CVE-2021-47099", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47102", "CVE-2021-47104", "CVE-2021-47105", "CVE-2021-47107", "CVE-2021-47108", "CVE-2022-4744", "CVE-2022-48626", "CVE-2022-48627", "CVE-2022-48628", "CVE-2022-48629", "CVE-2022-48630", "CVE-2023-0160", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-4881", "CVE-2023-52447", "CVE-2023-52450", "CVE-2023-52453", "CVE-2023-52454", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52467", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52481", "CVE-2023-52482", "CVE-2023-52484", "CVE-2023-52486", "CVE-2023-52492", "CVE-2023-52493", "CVE-2023-52494", "CVE-2023-52497", "CVE-2023-52500", "CVE-2023-52501", "CVE-2023-52502", "CVE-2023-52504", "CVE-2023-52507", "CVE-2023-52508", "CVE-2023-52509", "CVE-2023-52510", "CVE-2023-52511", "CVE-2023-52513", "CVE-2023-52515", "CVE-2023-52517", "CVE-2023-52518", "CVE-2023-52519", "CVE-2023-52520", "CVE-2023-52523", "CVE-2023-52524", "CVE-2023-52525", "CVE-2023-52528", "CVE-2023-52529", "CVE-2023-52530", "CVE-2023-52531", "CVE-2023-52532", "CVE-2023-52559", "CVE-2023-52563", "CVE-2023-52564", "CVE-2023-52566", "CVE-2023-52567", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52575", "CVE-2023-52576", "CVE-2023-52582", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52591", "CVE-2023-52594", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52599", "CVE-2023-52600", "CVE-2023-52601", "CVE-2023-52602", "CVE-2023-52603", "CVE-2023-52604", "CVE-2023-52605", "CVE-2023-52606", "CVE-2023-52607", "CVE-2023-52608", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52617", "CVE-2023-52619", "CVE-2023-52621", "CVE-2023-52623", "CVE-2023-52628", "CVE-2023-52632", "CVE-2023-52637", "CVE-2023-52639", "CVE-2023-6270", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-0841", "CVE-2024-2201", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-25739", "CVE-2024-25742", "CVE-2024-26599", "CVE-2024-26600", "CVE-2024-26602", "CVE-2024-26607", "CVE-2024-26612", "CVE-2024-26614", "CVE-2024-26620", "CVE-2024-26627", "CVE-2024-26629", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26646", "CVE-2024-26651", "CVE-2024-26654", "CVE-2024-26659", "CVE-2024-26664", "CVE-2024-26667", "CVE-2024-26670", "CVE-2024-26695", "CVE-2024-26717");
  script_tag(name:"creation_date", value:"2024-05-07 01:00:26 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-17 19:34:01 +0000 (Wed, 17 Apr 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1466-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1466-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241466-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222952");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035122.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:1466-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various security bugfixes.

NOTE: This update has been retracted due to a bug in the BHI CPU sidechannel mitigation, which led to incorrect selection of other CPU mitigations.

The following security bugs were fixed:

- CVE-2021-46925: Fixed kernel panic caused by race of smc_sock (bsc#1220466).
- CVE-2021-46926: Fixed bug when detecting controllers in ALSA/hda/intel-sdw-acpi (bsc#1220478).
- CVE-2021-46927: Fixed assertion bug in nitro_enclaves: Use get_user_pages_unlocked() (bsc#1220443).
- CVE-2021-46929: Fixed use-after-free issue in sctp_sock_dump() (bsc#1220482).
- CVE-2021-46930: Fixed usb/mtu3 list_head check warning (bsc#1220484).
- CVE-2021-46931: Fixed wrong type casting in mlx5e_tx_reporter_dump_sq() (bsc#1220486).
- CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).
- CVE-2021-46934: Fixed a bug by validating user data in compat ioctl (bsc#1220469).
- CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).
- CVE-2021-47082: Fixed ouble free in tun_free_netdev() (bsc#1220969).
- CVE-2021-47083: Fixed a global-out-of-bounds issue in mediatek: (bsc#1220917).
- CVE-2021-47087: Fixed incorrect page free bug in tee/optee (bsc#1220954).
- CVE-2021-47091: Fixed locking in ieee80211_start_ap()) error path (bsc#1220959).
- CVE-2021-47093: Fixed memleak on registration failure in intel_pmc_core (bsc#1220978).
- CVE-2021-47094: Fixed possible memory leak in KVM x86/mmu (bsc#1221551).
- CVE-2021-47095: Fixed missing initialization in ipmi/ssif (bsc#1220979).
- CVE-2021-47096: Fixed uninitalized user_pversion in ALSA rawmidi (bsc#1220981).
- CVE-2021-47097: Fixed stack out of bound access in elantech_change_report_id() (bsc#1220982).
- CVE-2021-47098: Fixed integer overflow/underflow in hysteresis calculations hwmon: (lm90) (bsc#1220983).
- CVE-2021-47099: Fixed BUG_ON assertion in veth when skb entering GRO are cloned (bsc#1220955).
- CVE-2021-47100: Fixed UAF when uninstall in ipmi (bsc#1220985).
- CVE-2021-47101: Fixed uninit-value in asix_mdio_read() (bsc#1220987).
- CVE-2021-47102: Fixed incorrect structure access In line: upper = info->upper_dev in net/marvell/prestera (bsc#1221009).
- CVE-2021-47104: Fixed memory leak in qib_user_sdma_queue_pkts() (bsc#1220960).
- CVE-2021-47105: Fixed potential memory leak in ice/xsk (bsc#1220961).
- CVE-2021-47107: Fixed READDIR buffer overflow in NFSD (bsc#1220965).
- CVE-2021-47108: Fixed possible NULL pointer dereference for mtk_hdmi_conf in drm/mediatek (bsc#1220986).
- CVE-2022-4744: Fixed double-free that could lead to DoS or privilege escalation in TUN/TAP device driver functionality (bsc#1209635).
- CVE-2022-48626: Fixed a potential use-after-free on remove path moxart (bsc#1220366).
- CVE-2022-48627: Fixed a memory overlapping when deleting chars in the buffer (bsc#1220845).
- CVE-2022-48628: Fixed possible lock ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.47.1", rls:"openSUSELeap15.5"))) {
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
