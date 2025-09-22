# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2184.1");
  script_cve_id("CVE-2021-46933", "CVE-2021-46955", "CVE-2021-47074", "CVE-2021-47113", "CVE-2021-47131", "CVE-2021-47162", "CVE-2021-47171", "CVE-2021-47188", "CVE-2021-47206", "CVE-2021-47220", "CVE-2021-47229", "CVE-2021-47231", "CVE-2021-47235", "CVE-2021-47236", "CVE-2021-47237", "CVE-2021-47238", "CVE-2021-47239", "CVE-2021-47245", "CVE-2021-47246", "CVE-2021-47248", "CVE-2021-47249", "CVE-2021-47250", "CVE-2021-47252", "CVE-2021-47254", "CVE-2021-47258", "CVE-2021-47260", "CVE-2021-47261", "CVE-2021-47265", "CVE-2021-47269", "CVE-2021-47274", "CVE-2021-47276", "CVE-2021-47277", "CVE-2021-47280", "CVE-2021-47281", "CVE-2021-47284", "CVE-2021-47285", "CVE-2021-47288", "CVE-2021-47301", "CVE-2021-47302", "CVE-2021-47305", "CVE-2021-47307", "CVE-2021-47308", "CVE-2021-47310", "CVE-2021-47311", "CVE-2021-47314", "CVE-2021-47315", "CVE-2021-47319", "CVE-2021-47320", "CVE-2021-47321", "CVE-2021-47323", "CVE-2021-47324", "CVE-2021-47330", "CVE-2021-47334", "CVE-2021-47337", "CVE-2021-47343", "CVE-2021-47344", "CVE-2021-47345", "CVE-2021-47347", "CVE-2021-47352", "CVE-2021-47353", "CVE-2021-47355", "CVE-2021-47356", "CVE-2021-47357", "CVE-2021-47361", "CVE-2021-47362", "CVE-2021-47369", "CVE-2021-47375", "CVE-2021-47378", "CVE-2021-47382", "CVE-2021-47383", "CVE-2021-47391", "CVE-2021-47397", "CVE-2021-47400", "CVE-2021-47401", "CVE-2021-47404", "CVE-2021-47409", "CVE-2021-47416", "CVE-2021-47423", "CVE-2021-47424", "CVE-2021-47431", "CVE-2021-47435", "CVE-2021-47436", "CVE-2021-47456", "CVE-2021-47458", "CVE-2021-47460", "CVE-2021-47469", "CVE-2021-47472", "CVE-2021-47473", "CVE-2021-47478", "CVE-2021-47480", "CVE-2021-47483", "CVE-2021-47485", "CVE-2021-47495", "CVE-2021-47496", "CVE-2021-47497", "CVE-2021-47500", "CVE-2021-47506", "CVE-2021-47509", "CVE-2021-47511", "CVE-2021-47523", "CVE-2021-47541", "CVE-2021-47548", "CVE-2021-47565", "CVE-2022-48636", "CVE-2022-48650", "CVE-2022-48672", "CVE-2022-48686", "CVE-2022-48697", "CVE-2022-48702", "CVE-2022-48704", "CVE-2022-48708", "CVE-2022-48710", "CVE-2023-0160", "CVE-2023-1829", "CVE-2023-42755", "CVE-2023-47233", "CVE-2023-52527", "CVE-2023-52586", "CVE-2023-52591", "CVE-2023-52646", "CVE-2023-52653", "CVE-2023-52655", "CVE-2023-52664", "CVE-2023-52685", "CVE-2023-52686", "CVE-2023-52691", "CVE-2023-52696", "CVE-2023-52698", "CVE-2023-52703", "CVE-2023-52730", "CVE-2023-52732", "CVE-2023-52741", "CVE-2023-52742", "CVE-2023-52747", "CVE-2023-52759", "CVE-2023-52774", "CVE-2023-52781", "CVE-2023-52796", "CVE-2023-52803", "CVE-2023-52821", "CVE-2023-52864", "CVE-2023-52865", "CVE-2023-52867", "CVE-2023-52875", "CVE-2023-52880", "CVE-2024-0639", "CVE-2024-26625", "CVE-2024-26739", "CVE-2024-26752", "CVE-2024-26775", "CVE-2024-26791", "CVE-2024-26828", "CVE-2024-26846", "CVE-2024-26874", "CVE-2024-26876", "CVE-2024-26900", "CVE-2024-26915", "CVE-2024-26920", "CVE-2024-26921", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26957", "CVE-2024-26958", "CVE-2024-26984", "CVE-2024-26996", "CVE-2024-27008", "CVE-2024-27054", "CVE-2024-27059", "CVE-2024-27062", "CVE-2024-27388", "CVE-2024-27396", "CVE-2024-27398", "CVE-2024-27401", "CVE-2024-27419", "CVE-2024-27436", "CVE-2024-35789", "CVE-2024-35791", "CVE-2024-35809", "CVE-2024-35811", "CVE-2024-35830", "CVE-2024-35849", "CVE-2024-35877", "CVE-2024-35878", "CVE-2024-35887", "CVE-2024-35895", "CVE-2024-35914", "CVE-2024-35932", "CVE-2024-35935", "CVE-2024-35936", "CVE-2024-35944", "CVE-2024-35955", "CVE-2024-35969", "CVE-2024-35982", "CVE-2024-36015", "CVE-2024-36029", "CVE-2024-36954");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-09-19T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-18 15:50:37 +0000 (Thu, 18 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2184-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242184-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1197894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225764");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035716.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).
- CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when fragmenting IPv4 packets (bsc#1220513).
- CVE-2021-47074: Fixed memory leak in nvme_loop_create_ctrl() (bsc#1220854).
- CVE-2021-47113: Abort btrfs rename_exchange if we fail to insert the second ref (bsc#1221543).
- CVE-2021-47131: Fixed a use-after-free after the TLS device goes down and up (bsc#1221545).
- CVE-2021-47206: Check return value after calling platform_get_resource() (bsc#1222894).
- CVE-2021-47238: Fixed memory leak in ip_mc_add1_src (bsc#1224847)
- CVE-2021-47245: Fixed out of bounds when parsing TCP options (bsc#1224838)
- CVE-2021-47246: Fixed page reclaim for dead peer hairpin (CVE-2021-47246 bsc#1224831).
- CVE-2021-47249: Fixed memory leak in rds_recvmsg (bsc#1224880)
- CVE-2021-47250: Fixed memory leak in netlbl_cipsov4_add_std (bsc#1224827)
- CVE-2021-47265: Verify port when creating flow rule (bsc#1224957)
- CVE-2021-47277: Avoid speculation-based attacks from out-of-range memslot accesses (bsc#1224960).
- CVE-2021-47281: Fixed race of snd_seq_timer_open() (bsc#1224983).
- CVE-2021-47334: Fixed two use after free in ibmasm_init_one (bsc#1225112).
- CVE-2021-47352: Add validation for used length (bsc#1225124).
- CVE-2021-47355: Fixed possible use-after-free in nicstar_cleanup() (bsc#1225141).
- CVE-2021-47357: Fixed possible use-after-free in ia_module_exit() (bsc#1225144).
- CVE-2021-47361: Fixed error handling in mcb_alloc_bus() (bsc#1225151).
- CVE-2021-47362: Update intermediate power state for SI (bsc#1225153).
- CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free (bsc#1225201).
- CVE-2021-47383: Fixed out-of-bound vmalloc access in imageblit (bsc#1225208).
- CVE-2021-47397: Break out if skb_header_pointer returns NULL in sctp_rcv_ootb (bsc#1225082)
- CVE-2021-47401: Fixed stack information leak (bsc#1225242).
- CVE-2021-47423: Fixed file release memory leak (bsc#1225366).
- CVE-2021-47431: Fixed gart.bo pin_count leak (bsc#1225390).
- CVE-2021-47469: Add SPI fix commit to be ignored (bsc#1225347)
- CVE-2021-47483: Fixed possible double-free in regcache_rbtree_exit() (bsc#1224907).
- CVE-2021-47496: Fix flipped sign in tls_err_abort() calls (bsc#1225354)
- CVE-2021-47497: Fixed shift-out-of-bound (UBSAN) with byte size cells (bsc#1225355).
- CVE-2021-47500: Fixed trigger reference couting (bsc#1225360).
- CVE-2021-47509: Limit the period size to 16MB (bsc#1225409).
- CVE-2021-47511: Fixed negative period/buffer sizes (bsc#1225411).
- CVE-2021-47548: Fixed a possible array out-of=bounds (bsc#1225506)
- CVE-2022-48672: Fixed off-by-one error in unflatten_dt_nodes() (CVE-2022-48672 bsc#1223931).
- CVE-2022-48686: Fixed UAF when detecting digest errors ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.219.1", rls:"SLES12.0SP5"))) {
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
