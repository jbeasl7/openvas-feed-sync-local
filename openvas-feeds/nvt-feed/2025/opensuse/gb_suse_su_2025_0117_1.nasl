# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856932");
  script_cve_id("CVE-2024-26924", "CVE-2024-27397", "CVE-2024-35839", "CVE-2024-36908", "CVE-2024-36915", "CVE-2024-39480", "CVE-2024-41042", "CVE-2024-44934", "CVE-2024-44996", "CVE-2024-47678", "CVE-2024-49854", "CVE-2024-49884", "CVE-2024-49915", "CVE-2024-50016", "CVE-2024-50018", "CVE-2024-50039", "CVE-2024-50047", "CVE-2024-50143", "CVE-2024-50154", "CVE-2024-50202", "CVE-2024-50203", "CVE-2024-50211", "CVE-2024-50228", "CVE-2024-50256", "CVE-2024-50262", "CVE-2024-50272", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-53050", "CVE-2024-53064", "CVE-2024-53090", "CVE-2024-53099", "CVE-2024-53103", "CVE-2024-53105", "CVE-2024-53111", "CVE-2024-53113", "CVE-2024-53117", "CVE-2024-53118", "CVE-2024-53119", "CVE-2024-53120", "CVE-2024-53122", "CVE-2024-53125", "CVE-2024-53126", "CVE-2024-53127", "CVE-2024-53129", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53133", "CVE-2024-53134", "CVE-2024-53136", "CVE-2024-53141", "CVE-2024-53142", "CVE-2024-53144", "CVE-2024-53146", "CVE-2024-53148", "CVE-2024-53150", "CVE-2024-53151", "CVE-2024-53154", "CVE-2024-53155", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53158", "CVE-2024-53159", "CVE-2024-53160", "CVE-2024-53161", "CVE-2024-53162", "CVE-2024-53166", "CVE-2024-53169", "CVE-2024-53171", "CVE-2024-53173", "CVE-2024-53174", "CVE-2024-53179", "CVE-2024-53180", "CVE-2024-53188", "CVE-2024-53190", "CVE-2024-53191", "CVE-2024-53200", "CVE-2024-53201", "CVE-2024-53202", "CVE-2024-53206", "CVE-2024-53207", "CVE-2024-53208", "CVE-2024-53209", "CVE-2024-53210", "CVE-2024-53213", "CVE-2024-53214", "CVE-2024-53215", "CVE-2024-53216", "CVE-2024-53217", "CVE-2024-53222", "CVE-2024-53224", "CVE-2024-53229", "CVE-2024-53234", "CVE-2024-53237", "CVE-2024-53240", "CVE-2024-53241", "CVE-2024-56536", "CVE-2024-56539", "CVE-2024-56549", "CVE-2024-56551", "CVE-2024-56562", "CVE-2024-56566", "CVE-2024-56567", "CVE-2024-56576", "CVE-2024-56582", "CVE-2024-56599", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56645", "CVE-2024-56667", "CVE-2024-56752", "CVE-2024-56754", "CVE-2024-56755", "CVE-2024-56756", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-01-16 05:00:50 +0000 (Thu, 16 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.kernel.org/show_bug.cgi?id=216322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235550");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020131.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2025:0117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
- CVE-2024-27397: netfilter: nf_tables: use timestamp to check for set element timeout (bsc#1224095).
- CVE-2024-35839: kABI fix for netfilter: bridge: replace physindev with physinif in nf_bridge_info (bsc#1224726).
- CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
- CVE-2024-41042: Prefer nft_chain_validate (bsc#1228526).
- CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when removing port (bsc#1229809).
- CVE-2024-44996: vsock: fix recursive ->recvmsg calls (bsc#1230205).
- CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
- CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs (bsc#1232419).
- CVE-2024-50039: kABI: Restore deleted EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).
- CVE-2024-50202: nilfs2: propagate directory read errors from nilfs_find_entry() (bsc#1233324).
- CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
- CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
- CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized delayed_work on cache_ctr error (bsc#1233467).
- CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
- CVE-2024-53050: drm/i915/hdcp: Add encoder check in hdcp2_get_capability (bsc#1233546).
- CVE-2024-53064: idpf: fix idpf_vc_core_init error path (bsc#1233558).
- CVE-2024-53090: afs: Fix lock recursion (bsc#1233637).
- CVE-2024-53099: bpf: Check validity of link->type in bpf_link_show_fdinfo() (bsc#1233772).
- CVE-2024-53105: mm: page_alloc: move mlocked flag clearance into free_pages_prepare() (bsc#1234069).
- CVE-2024-53111: mm/mremap: fix address wraparound in move_page_tables() (bsc#1234086).
- CVE-2024-53113: mm: fix NULL pointer dereference in alloc_pages_bulk_noprof (bsc#1234077).
- CVE-2024-53117: virtio/vsock: Improve MSG_ZEROCOPY error handling (bsc#1234079).
- CVE-2024-53118: vsock: Fix sk_error_queue memory leak (bsc#1234071).
- CVE-2024-53119: virtio/vsock: Fix accept_queue memory leak (bsc#1234073).
- CVE-2024-53122: mptcp: cope racing subflow creation in mptcp_rcv_space_adjust (bsc#1234076).
- CVE-2024-53125: bpf: sync_linked_regs() must preserve subreg_def (bsc#1234156).
- CVE-2024-53130: nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (bsc#1234219).
- CVE-2024-53131: nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (bsc#1234220).
- CVE-2024-53133: drm/amd/display: Handle dml allocation failure to avoid crash (bsc#1234221)
- CVE-2024-53134: pmdomain: imx93-blk-ctrl: correct remove path (bsc#1234159).
- CVE-2024-53141: netfilter: ipset: add ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~6.4.0~150600.8.23.1", rls:"openSUSELeap15.6"))) {
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
