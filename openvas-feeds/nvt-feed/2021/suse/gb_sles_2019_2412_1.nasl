# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2412.1");
  script_cve_id("CVE-2017-18551", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-10207", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15099", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-05 13:21:05 +0000 (Thu, 05 Sep 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2412-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2412-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192412-1.html");
  script_xref(name:"URL", value:"http://acl.bestbits.at");
  script_xref(name:"URL", value:"https://bugzilla.kernel.org/show_bug.cgi?id=202935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1047238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145302");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150933");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-September/005941.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2412-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following new features were implemented:

- jsc#SLE-4875: [CML] New device IDs for CML
- jsc#SLE-7294: Add cpufreq driver for Raspberry Pi
- fate#322438: Integrate P9 XIVE support (on PowerVM only)
- fate#322447: Add memory protection keys (MPK) support on POWER (on PowerVM only)
- fate#322448, fate#321438: P9 hardware counter (performance counters) support (on PowerVM only)
- fate#325306, fate#321840: Reduce memory required to boot capture kernel while using fadump
- fate#326869: perf: pmu mem_load/store event support

The following security bugs were fixed:

- CVE-2017-18551: There was an out of bounds write in the function i2c_smbus_xfer_emulated. (bsc#1146163).
- CVE-2018-20976: A use after free existed, related to xfs_fs_fill_super failure. (bsc#1146285)
- CVE-2018-21008: A use-after-free can be caused by the function rsi_mac80211_detach (bsc#1149591).
- CVE-2019-9456: In Pixel C USB monitor driver there was a possible OOB write due to a missing bounds check. This could have lead to local escalation of privilege with System execution privileges needed. (bsc#1150025 CVE-2019-9456).
- CVE-2019-10207: Fix a NULL pointer dereference in hci_uart bluetooth driver (bsc#1142857 bsc#1123959).
- CVE-2019-14814, CVE-2019-14815, CVE-2019-14816: Fix three heap-based buffer overflows in marvell wifi chip driver kernel, that allowed local users to cause a denial of service (system crash) or possibly execute arbitrary code. (bnc#1146516)
- CVE-2019-14835: Fix QEMU-KVM Guest to Host Kernel Escape. (bsc#1150112).
- CVE-2019-15030, CVE-2019-15031: On the powerpc platform, a local user could read vector registers of other users' processes via an interrupt. (bsc#1149713)
- CVE-2019-15090: In the qedi_dbg_* family of functions, there was an out-of-bounds read. (bsc#1146399)
- CVE-2019-15098: USB driver net/wireless/ath/ath6kl/usb.c had a NULL pointer dereference via an incomplete address in an endpoint descriptor. (bsc#1146378).
- CVE-2019-15099: drivers/net/wireless/ath/ath10k/usb.c had a NULL pointer dereference via an incomplete address in an endpoint descriptor. (bsc#1146368)
- CVE-2019-15117: parse_audio_mixer_unit in sound/usb/mixer.c in the Linux kernel mishandled a short descriptor, leading to out-of-bounds memory access. (bsc#1145920).
- CVE-2019-15118: check_input_term in sound/usb/mixer.c in the Linux kernel mishandled recursion, leading to kernel stack exhaustion. (bsc#1145922).
- CVE-2019-15211: There was a use-after-free caused by a malicious USB device in the drivers/media/v4l2-core/v4l2-dev.c driver because drivers/media/radio/radio-raremono.c did not properly allocate memory. (bsc#1146519).
- CVE-2019-15212: There was a double-free caused by a malicious USB device in the drivers/usb/misc/rio500.c driver. (bsc#1051510 bsc#1146391).
- CVE-2019-15214: There was a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.32.1", rls:"SLES12.0SP4"))) {
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
