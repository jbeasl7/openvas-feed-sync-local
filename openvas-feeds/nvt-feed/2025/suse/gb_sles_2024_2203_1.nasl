# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2203.1");
  script_cve_id("CVE-2023-0160", "CVE-2023-52434", "CVE-2023-52458", "CVE-2023-52472", "CVE-2023-52503", "CVE-2023-52616", "CVE-2023-52618", "CVE-2023-52631", "CVE-2023-52635", "CVE-2023-52640", "CVE-2023-52641", "CVE-2023-52645", "CVE-2023-52652", "CVE-2023-52653", "CVE-2023-52654", "CVE-2023-52655", "CVE-2023-52657", "CVE-2023-52658", "CVE-2023-52659", "CVE-2023-52660", "CVE-2023-52661", "CVE-2023-52662", "CVE-2023-52663", "CVE-2023-52664", "CVE-2023-52667", "CVE-2023-52669", "CVE-2023-52670", "CVE-2023-52671", "CVE-2023-52673", "CVE-2023-52674", "CVE-2023-52675", "CVE-2023-52676", "CVE-2023-52678", "CVE-2023-52679", "CVE-2023-52680", "CVE-2023-52681", "CVE-2023-52683", "CVE-2023-52685", "CVE-2023-52686", "CVE-2023-52687", "CVE-2023-52690", "CVE-2023-52691", "CVE-2023-52692", "CVE-2023-52693", "CVE-2023-52694", "CVE-2023-52695", "CVE-2023-52696", "CVE-2023-52697", "CVE-2023-52698", "CVE-2023-52771", "CVE-2023-52772", "CVE-2023-52860", "CVE-2023-52882", "CVE-2023-6238", "CVE-2023-7042", "CVE-2024-0639", "CVE-2024-21823", "CVE-2024-22099", "CVE-2024-23848", "CVE-2024-24861", "CVE-2024-25739", "CVE-2024-26601", "CVE-2024-26611", "CVE-2024-26614", "CVE-2024-26632", "CVE-2024-26638", "CVE-2024-26642", "CVE-2024-26643", "CVE-2024-26650", "CVE-2024-26654", "CVE-2024-26656", "CVE-2024-26657", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26674", "CVE-2024-26679", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26692", "CVE-2024-26704", "CVE-2024-26714", "CVE-2024-26726", "CVE-2024-26731", "CVE-2024-26733", "CVE-2024-26737", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26742", "CVE-2024-26760", "CVE-2024-267600", "CVE-2024-26761", "CVE-2024-26764", "CVE-2024-26769", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26774", "CVE-2024-26775", "CVE-2024-26783", "CVE-2024-26786", "CVE-2024-26791", "CVE-2024-26793", "CVE-2024-26794", "CVE-2024-26802", "CVE-2024-26805", "CVE-2024-26807", "CVE-2024-26815", "CVE-2024-26816", "CVE-2024-26822", "CVE-2024-26832", "CVE-2024-26836", "CVE-2024-26844", "CVE-2024-26846", "CVE-2024-26853", "CVE-2024-26854", "CVE-2024-26855", "CVE-2024-26856", "CVE-2024-26857", "CVE-2024-26858", "CVE-2024-26860", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26866", "CVE-2024-26868", "CVE-2024-26870", "CVE-2024-26878", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26899", "CVE-2024-26900", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26906", "CVE-2024-26909", "CVE-2024-26921", "CVE-2024-26922", "CVE-2024-26923", "CVE-2024-26925", "CVE-2024-26928", "CVE-2024-26932", "CVE-2024-26933", "CVE-2024-26934", "CVE-2024-26935", "CVE-2024-26937", "CVE-2024-26938", "CVE-2024-26940", "CVE-2024-26943", "CVE-2024-26945", "CVE-2024-26946", "CVE-2024-26948", "CVE-2024-26949", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26957", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26961", "CVE-2024-26962", "CVE-2024-26963", "CVE-2024-26964", "CVE-2024-26972", "CVE-2024-26973", "CVE-2024-26978", "CVE-2024-26981", "CVE-2024-26982", "CVE-2024-26983", "CVE-2024-26984", "CVE-2024-26986", "CVE-2024-26988", "CVE-2024-26989", "CVE-2024-26990", "CVE-2024-26991", "CVE-2024-26992", "CVE-2024-26993", "CVE-2024-26994", "CVE-2024-26995", "CVE-2024-26996", "CVE-2024-26997", "CVE-2024-26999", "CVE-2024-27000", "CVE-2024-27001", "CVE-2024-27002", "CVE-2024-27003", "CVE-2024-27004", "CVE-2024-27008", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27022", "CVE-2024-27027", "CVE-2024-27028", "CVE-2024-27029", "CVE-2024-27030", "CVE-2024-27031", "CVE-2024-27036", "CVE-2024-27046", "CVE-2024-27056", "CVE-2024-27057", "CVE-2024-27062", "CVE-2024-27067", "CVE-2024-27080", "CVE-2024-27388", "CVE-2024-27389", "CVE-2024-27393", "CVE-2024-27395", "CVE-2024-27396", "CVE-2024-27398", "CVE-2024-27399", "CVE-2024-27400", "CVE-2024-27401", "CVE-2024-27405", "CVE-2024-27408", "CVE-2024-27410", "CVE-2024-27411", "CVE-2024-27412", "CVE-2024-27413", "CVE-2024-27416", "CVE-2024-27417", "CVE-2024-27418", "CVE-2024-27431", "CVE-2024-27432", "CVE-2024-27434", "CVE-2024-27435", "CVE-2024-27436", "CVE-2024-35784", "CVE-2024-35786", "CVE-2024-35788", "CVE-2024-35789", "CVE-2024-35790", "CVE-2024-35791", "CVE-2024-35794", "CVE-2024-35795", "CVE-2024-35796", "CVE-2024-35799", "CVE-2024-35800", "CVE-2024-35801", "CVE-2024-35803", "CVE-2024-35804", "CVE-2024-35806", "CVE-2024-35808", "CVE-2024-35809", "CVE-2024-35810", "CVE-2024-35811", "CVE-2024-35812", "CVE-2024-35813", "CVE-2024-35814", "CVE-2024-35815", "CVE-2024-35817", "CVE-2024-35819", "CVE-2024-35821", "CVE-2024-35822", "CVE-2024-35823", "CVE-2024-35824", "CVE-2024-35825", "CVE-2024-35828", "CVE-2024-35829", "CVE-2024-35830", "CVE-2024-35833", "CVE-2024-35834", "CVE-2024-35835", "CVE-2024-35836", "CVE-2024-35837", "CVE-2024-35838", "CVE-2024-35841", "CVE-2024-35842", "CVE-2024-35845", "CVE-2024-35847", "CVE-2024-35849", "CVE-2024-35850", "CVE-2024-35851", "CVE-2024-35852", "CVE-2024-35854", "CVE-2024-35860", "CVE-2024-35861", "CVE-2024-35862", "CVE-2024-35863", "CVE-2024-35864", "CVE-2024-35865", "CVE-2024-35866", "CVE-2024-35867", "CVE-2024-35868", "CVE-2024-35869", "CVE-2024-35870", "CVE-2024-35872", "CVE-2024-35875", "CVE-2024-35877", "CVE-2024-35878", "CVE-2024-35879", "CVE-2024-35883", "CVE-2024-35885", "CVE-2024-35887", "CVE-2024-35889", "CVE-2024-35891", "CVE-2024-35895", "CVE-2024-35901", "CVE-2024-35903", "CVE-2024-35904", "CVE-2024-35905", "CVE-2024-35907", "CVE-2024-35909", "CVE-2024-35911", "CVE-2024-35912", "CVE-2024-35914", "CVE-2024-35915", "CVE-2024-35916", "CVE-2024-35917", "CVE-2024-35921", "CVE-2024-35922", "CVE-2024-35924", "CVE-2024-35927", "CVE-2024-35928", "CVE-2024-35930", "CVE-2024-35931", "CVE-2024-35932", "CVE-2024-35933", "CVE-2024-35935", "CVE-2024-35936", "CVE-2024-35937", "CVE-2024-35938", "CVE-2024-35940", "CVE-2024-35943", "CVE-2024-35944", "CVE-2024-35945", "CVE-2024-35946", "CVE-2024-35947", "CVE-2024-35950", "CVE-2024-35951", "CVE-2024-35952", "CVE-2024-35953", "CVE-2024-35954", "CVE-2024-35955", "CVE-2024-35956", "CVE-2024-35958", "CVE-2024-35959", "CVE-2024-35960", "CVE-2024-35961", "CVE-2024-35963", "CVE-2024-35964", "CVE-2024-35965", "CVE-2024-35966", "CVE-2024-35967", "CVE-2024-35969", "CVE-2024-35971", "CVE-2024-35972", "CVE-2024-35973", "CVE-2024-35974", "CVE-2024-35975", "CVE-2024-35977", "CVE-2024-35978", "CVE-2024-35981", "CVE-2024-35982", "CVE-2024-35984", "CVE-2024-35986", "CVE-2024-35989", "CVE-2024-35990", "CVE-2024-35991", "CVE-2024-35992", "CVE-2024-35995", "CVE-2024-35997", "CVE-2024-35999", "CVE-2024-36002", "CVE-2024-36006", "CVE-2024-36007", "CVE-2024-36009", "CVE-2024-36011", "CVE-2024-36012", "CVE-2024-36013", "CVE-2024-36014", "CVE-2024-36015", "CVE-2024-36016", "CVE-2024-36018", "CVE-2024-36019", "CVE-2024-36020", "CVE-2024-36021", "CVE-2024-36025", "CVE-2024-36026", "CVE-2024-36029", "CVE-2024-36030", "CVE-2024-36032", "CVE-2024-36880", "CVE-2024-36885", "CVE-2024-36890", "CVE-2024-36891", "CVE-2024-36893", "CVE-2024-36894", "CVE-2024-36895", "CVE-2024-36896", "CVE-2024-36897", "CVE-2024-36898", "CVE-2024-36906", "CVE-2024-36918", "CVE-2024-36921", "CVE-2024-36922", "CVE-2024-36928", "CVE-2024-36930", "CVE-2024-36931", "CVE-2024-36936", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36942", "CVE-2024-36944", "CVE-2024-36947", "CVE-2024-36949", "CVE-2024-36950", "CVE-2024-36951", "CVE-2024-36955", "CVE-2024-36959");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-19 16:16:45 +0000 (Fri, 19 Sep 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2203-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2203-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242203-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226158");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019244.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2203-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system (bsc#1209657).
- CVE-2023-52434: Fixed potential OOBs in smb2_parse_contexts() (bsc#1220148).
- CVE-2023-52458: Fixed check that partition length needs to be aligned with block size (bsc#1220428).
- CVE-2023-52503: Fixed tee/amdtee use-after-free vulnerability in amdtee_close_session (bsc#1220915).
- CVE-2023-52618: Fixed string overflow in block/rnbd-srv (bsc#1221615).
- CVE-2023-52631: Fixed an NULL dereference bug (bsc#1222264 CVE-2023-52631).
- CVE-2023-52635: Fixed PM/devfreq to synchronize devfreq_monitor_[start/stop] (bsc#1222294).
- CVE-2023-52640: Fixed out-of-bounds in ntfs_listxattr (bsc#1222301).
- CVE-2023-52641: Fixed NULL ptr dereference checking at the end of attr_allocate_frame() (bsc#1222303)
- CVE-2023-52645: Fixed pmdomain/mediatek race conditions with genpd (bsc#1223033).
- CVE-2023-52652: Fixed NTB for possible name leak in ntb_register_device() (bsc#1223686).
- CVE-2023-52659: Fixed to pfn_to_kaddr() not treated as a 64-bit type (bsc#1224442).
- CVE-2023-52674: Add clamp() in scarlett2_mixer_ctl_put() (bsc#1224727).
- CVE-2023-52680: Fixed missing error checks to *_ctl_get() (bsc#1224608).
- CVE-2023-52692: Fixed missing error check to scarlett2_usb_set_config() (bsc#1224628).
- CVE-2023-52698: Fixed memory leak in netlbl_calipso_add_pass() (CVE-2023-52698 bsc#1224621)
- CVE-2023-52771: Fixed delete_endpoint() vs parent unregistration race (bsc#1225007).
- CVE-2023-52772: Fixed use-after-free in unix_stream_read_actor() (bsc#1224989).
- CVE-2023-52860: Fixed null pointer dereference in hisi_hns3 (bsc#1224936).
- CVE-2023-6238: Fixed kcalloc() arguments order (bsc#1217384).
- CVE-2023-7042: Fixed a null-pointer-dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() (bsc#1218336).
- CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock found in sctp_auto_asconf_init in net/sctp/socket.c (bsc#1218917).
- CVE-2024-21823: Fixed safety flag to struct ends (bsc#1223625).
- CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
- CVE-2024-23848: Fixed media/cec for possible use-after-free in cec_queue_msg_fh (bsc#1219104).
- CVE-2024-24861: Fixed an overflow due to race condition in media/xc4000 device driver in xc4000 xc4000_get_frequency() function (bsc#1219623).
- CVE-2024-25739: Fixed possible crash in create_empty_lvol() in drivers/mtd/ubi/vtbl.c (bsc#1219834).
- CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
- CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
- CVE-2024-26632: Fixed iterating over an empty bio with bio_for_each_folio_all (bsc#1221635).
- CVE-2024-26638: Fixed ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.7.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.7.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.7.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.7.3.150600.12.2.7", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.7.3", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.7.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.7.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.7.3", rls:"SLES15.0SP6"))) {
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
