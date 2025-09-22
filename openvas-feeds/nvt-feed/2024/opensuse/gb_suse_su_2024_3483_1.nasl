# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856522");
  script_cve_id("CVE-2021-4204", "CVE-2021-4441", "CVE-2021-47106", "CVE-2021-47517", "CVE-2021-47546", "CVE-2022-0500", "CVE-2022-23222", "CVE-2022-38457", "CVE-2022-40133", "CVE-2022-4382", "CVE-2022-48645", "CVE-2022-48706", "CVE-2022-48808", "CVE-2022-48865", "CVE-2022-48868", "CVE-2022-48869", "CVE-2022-48870", "CVE-2022-48871", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48875", "CVE-2022-48878", "CVE-2022-48880", "CVE-2022-48881", "CVE-2022-48882", "CVE-2022-48883", "CVE-2022-48884", "CVE-2022-48885", "CVE-2022-48886", "CVE-2022-48887", "CVE-2022-48888", "CVE-2022-48889", "CVE-2022-48890", "CVE-2022-48891", "CVE-2022-48893", "CVE-2022-48896", "CVE-2022-48898", "CVE-2022-48899", "CVE-2022-48903", "CVE-2022-48904", "CVE-2022-48905", "CVE-2022-48906", "CVE-2022-48907", "CVE-2022-48909", "CVE-2022-48910", "CVE-2022-48912", "CVE-2022-48913", "CVE-2022-48914", "CVE-2022-48915", "CVE-2022-48916", "CVE-2022-48917", "CVE-2022-48918", "CVE-2022-48919", "CVE-2022-48920", "CVE-2022-48921", "CVE-2022-48923", "CVE-2022-48924", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48927", "CVE-2022-48928", "CVE-2022-48929", "CVE-2022-48930", "CVE-2022-48931", "CVE-2022-48932", "CVE-2022-48934", "CVE-2022-48937", "CVE-2022-48938", "CVE-2022-48939", "CVE-2022-48940", "CVE-2022-48941", "CVE-2022-48942", "CVE-2022-48943", "CVE-2023-3610", "CVE-2023-52458", "CVE-2023-52489", "CVE-2023-52498", "CVE-2023-52581", "CVE-2023-52859", "CVE-2023-52887", "CVE-2023-52889", "CVE-2023-52893", "CVE-2023-52894", "CVE-2023-52896", "CVE-2023-52898", "CVE-2023-52899", "CVE-2023-52900", "CVE-2023-52901", "CVE-2023-52904", "CVE-2023-52905", "CVE-2023-52906", "CVE-2023-52907", "CVE-2023-52908", "CVE-2023-52909", "CVE-2023-52910", "CVE-2023-52911", "CVE-2023-52912", "CVE-2023-52913", "CVE-2024-26631", "CVE-2024-26668", "CVE-2024-26669", "CVE-2024-26677", "CVE-2024-26735", "CVE-2024-26808", "CVE-2024-26812", "CVE-2024-26835", "CVE-2024-26851", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27016", "CVE-2024-27024", "CVE-2024-27079", "CVE-2024-27403", "CVE-2024-31076", "CVE-2024-35897", "CVE-2024-35902", "CVE-2024-35945", "CVE-2024-35971", "CVE-2024-36009", "CVE-2024-36013", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-36489", "CVE-2024-36929", "CVE-2024-36933", "CVE-2024-36936", "CVE-2024-36962", "CVE-2024-38554", "CVE-2024-38602", "CVE-2024-38662", "CVE-2024-39489", "CVE-2024-40905", "CVE-2024-40978", "CVE-2024-40980", "CVE-2024-40995", "CVE-2024-41000", "CVE-2024-41007", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41016", "CVE-2024-41020", "CVE-2024-41022", "CVE-2024-41035", "CVE-2024-41036", "CVE-2024-41038", "CVE-2024-41039", "CVE-2024-41042", "CVE-2024-41045", "CVE-2024-41056", "CVE-2024-41060", "CVE-2024-41062", "CVE-2024-41065", "CVE-2024-41068", "CVE-2024-41073", "CVE-2024-41079", "CVE-2024-41080", "CVE-2024-41087", "CVE-2024-41088", "CVE-2024-41089", "CVE-2024-41092", "CVE-2024-41093", "CVE-2024-41095", "CVE-2024-41097", "CVE-2024-41098", "CVE-2024-42069", "CVE-2024-42074", "CVE-2024-42076", "CVE-2024-42077", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42085", "CVE-2024-42086", "CVE-2024-42087", "CVE-2024-42089", "CVE-2024-42090", "CVE-2024-42092", "CVE-2024-42095", "CVE-2024-42097", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42104", "CVE-2024-42106", "CVE-2024-42107", "CVE-2024-42110", "CVE-2024-42114", "CVE-2024-42115", "CVE-2024-42119", "CVE-2024-42120", "CVE-2024-42121", "CVE-2024-42126", "CVE-2024-42127", "CVE-2024-42130", "CVE-2024-42137", "CVE-2024-42139", "CVE-2024-42142", "CVE-2024-42143", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42155", "CVE-2024-42156", "CVE-2024-42157", "CVE-2024-42158", "CVE-2024-42162", "CVE-2024-42223", "CVE-2024-42225", "CVE-2024-42228", "CVE-2024-42229", "CVE-2024-42230", "CVE-2024-42232", "CVE-2024-42236", "CVE-2024-42237", "CVE-2024-42238", "CVE-2024-42239", "CVE-2024-42240", "CVE-2024-42244", "CVE-2024-42246", "CVE-2024-42247", "CVE-2024-42268", "CVE-2024-42271", "CVE-2024-42274", "CVE-2024-42276", "CVE-2024-42277", "CVE-2024-42280", "CVE-2024-42281", "CVE-2024-42283", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42286", "CVE-2024-42287", "CVE-2024-42288", "CVE-2024-42289", "CVE-2024-42291", "CVE-2024-42292", "CVE-2024-42295", "CVE-2024-42301", "CVE-2024-42302", "CVE-2024-42308", "CVE-2024-42309", "CVE-2024-42310", "CVE-2024-42311", "CVE-2024-42312", "CVE-2024-42313", "CVE-2024-42315", "CVE-2024-42318", "CVE-2024-42319", "CVE-2024-42320", "CVE-2024-42322", "CVE-2024-43816", "CVE-2024-43818", "CVE-2024-43819", "CVE-2024-43821", "CVE-2024-43823", "CVE-2024-43829", "CVE-2024-43830", "CVE-2024-43831", "CVE-2024-43834", "CVE-2024-43837", "CVE-2024-43839", "CVE-2024-43841", "CVE-2024-43842", "CVE-2024-43846", "CVE-2024-43849", "CVE-2024-43853", "CVE-2024-43854", "CVE-2024-43856", "CVE-2024-43858", "CVE-2024-43860", "CVE-2024-43861", "CVE-2024-43863", "CVE-2024-43866", "CVE-2024-43867", "CVE-2024-43871", "CVE-2024-43872", "CVE-2024-43873", "CVE-2024-43879", "CVE-2024-43880", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-43884", "CVE-2024-43889", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43894", "CVE-2024-43895", "CVE-2024-43899", "CVE-2024-43900", "CVE-2024-43902", "CVE-2024-43903", "CVE-2024-43904", "CVE-2024-43905", "CVE-2024-43907", "CVE-2024-43908", "CVE-2024-43909", "CVE-2024-44938", "CVE-2024-44939", "CVE-2024-44947");
  script_tag(name:"creation_date", value:"2024-09-30 04:00:31 +0000 (Mon, 30 Sep 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 14:38:32 +0000 (Tue, 27 Aug 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3483-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3483-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243483-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230413");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/037089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:3483-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
- CVE-2024-36936: Touch soft lockup during memory accept (bsc#1225773).
- CVE-2022-48706: Do proper cleanup if IFCVF init fails (bsc#1225524).
- CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
- CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
- CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
- CVE-2024-36270: Fix reference in patches.suse/netfilter-tproxy-bail-out-if-IP-has-been-disabled-on.patch (bsc#1226798)
- CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).
- CVE-2024-43893: Check uartclk for zero to avoid divide by zero (bsc#1229759).
- CVE-2024-43821: Fix a possible null pointer dereference (bsc#1229315).
- CVE-2024-43900: Avoid use-after-free in load_firmware_cb() (bsc#1229756).
- CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).
- CVE-2024-44939: Fix null ptr deref in dtInsertEntry (bsc#1229820).
- CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).
- CVE-2024-42277: Avoid NULL deref in sprd_iommu_hw_en (bsc#1229409).
- CVE-2024-43902: Add null checker before passing variables (bsc#1229767).
- CVE-2024-43904: Add null checks for 'stream' and 'plane' before dereferencing (bsc#1229768)
- CVE-2024-43880: Put back removed metod in struct objagg_ops (bsc#1229481).
- CVE-2024-43884: Add error handling to pair_device() (bsc#1229739)
- CVE-2024-43899: Fix null pointer deref in dcn20_resource.c (bsc#1229754).
- CVE-2022-48920: Get rid of warning on transaction commit when using flushoncommit (bsc#1229658).
- CVE-2023-52906: Fix warning during failed attribute validation (bsc#1229527).
- CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
- CVE-2024-43866: Always drain health in shutdown callback (bsc#1229495).
- CVE-2024-26812: Struct virqfd kABI workaround (bsc#1222808).
- CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
- CVE-2024-27010: Fix mirred deadlock on device recursion (bsc#1223720).
- CVE-2022-48906: Correctly set DATA_FIN timeout when number of retransmits is large (bsc#1229605)
- CVE-2024-42155: Wipe copies of protected- and secure-keys (bsc#1228733).
- CVE-2024-42156: Wipe copies of clear-key structures on failure (bsc#1228722).
- CVE-2023-52899: Add exception protection processing for vd in axi_chan_handle_err function (bsc#1229569).
- CVE-2024-42158: Use kfree_sensitive() to fix Coccinelle warnings (bsc#1228720).
- CVE-2024-26631: Fix data-race in ipv6_mc_down / mld_ifc_work (bsc#1221630).
- CVE-2024-43873: Always initialize seqpacket_allow (bsc#1229488)
- CVE-2024-40905: Fix possible race in __fib6_drop_pcpu_from() (bsc#1227761)
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.80.2.150500.6.35.6", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.80.2.150500.6.35.6", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.80.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.80.2", rls:"openSUSELeap15.5"))) {
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
