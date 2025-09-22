# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1174.1");
  script_cve_id("CVE-2012-2372", "CVE-2012-4398", "CVE-2013-0160", "CVE-2013-1059", "CVE-2013-1774", "CVE-2013-1819", "CVE-2013-1929", "CVE-2013-1979", "CVE-2013-2146", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2206", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-2929", "CVE-2013-2930", "CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-3301", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4299", "CVE-2013-4345", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4514", "CVE-2013-4515", "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-4592", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6378", "CVE-2013-6380", "CVE-2013-6382", "CVE-2013-6383", "CVE-2013-6463", "CVE-2013-6885", "CVE-2013-7027", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7339", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-0131", "CVE-2014-0155", "CVE-2014-0181", "CVE-2014-0196", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1739", "CVE-2014-1874", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153", "CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-3917", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4508", "CVE-2014-4608", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5077", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-7822", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-7970", "CVE-2014-8086", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8369", "CVE-2014-8559", "CVE-2014-8709", "CVE-2014-8884", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1421", "CVE-2015-1593", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-03-16 14:19:01 +0000 (Mon, 16 Mar 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1174-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1174-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151174-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/599263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/708296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/733022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/745640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/755743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/760407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/763463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/763968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/765523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/767610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/769035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/769644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/770541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/774818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/779488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/783475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/785901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/787843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/793727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/794824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/801341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/801427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/803320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/804482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/804609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/804950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/810323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/810722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/821980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/832292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/832309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/832318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/832710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/836218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/836347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/836718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/836801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/838346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/838448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/838623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/841656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/842820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/844513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/850915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/855126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/855657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/855825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/861093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/861636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/861980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/893758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/898554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/900881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/918333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/924340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/925729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931850");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001471.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2015:1174-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to fix
various bugs and security issues.

The following security bugs have been fixed:

 *

 CVE-2014-1739: The media_device_enum_entities function in
 drivers/media/media-device.c in the Linux kernel before 3.14.6 does
 not initialize a certain data structure, which allows local users to
 obtain sensitive information from kernel memory by leveraging
 /dev/media0 read access for a MEDIA_IOC_ENUM_ENTITIES ioctl call
 (bnc#882804).

 *

 CVE-2014-4171: mm/shmem.c in the Linux kernel through 3.15.1 does not
 properly implement the interaction between range notification and
 hole punching, which allows local users to cause a denial of service
 (i_mutex hold) by using the mmap system call to access a hole, as
 demonstrated by interfering with intended shmem activity by blocking
 completion of (1) an MADV_REMOVE madvise call or (2) an
 FALLOC_FL_PUNCH_HOLE fallocate call (bnc#883518).

 *

 CVE-2014-4508: arch/x86/kernel/entry_32.S in the Linux kernel through
 3.15.1 on 32-bit x86 platforms, when syscall auditing is enabled and
 the sep CPU feature flag is set, allows local users to cause a denial
 of service (OOPS and system crash) via an invalid syscall number, as
 demonstrated by number 1000 (bnc#883724).

 *

 CVE-2014-4667: The sctp_association_free function in
 net/sctp/associola.c in the Linux kernel before 3.15.2 does not
 properly manage a certain backlog value, which allows remote
 attackers to cause a denial of service (socket outage) via a crafted
 SCTP packet (bnc#885422).

 *

 CVE-2014-4943: The PPPoL2TP feature in net/l2tp/l2tp_ppp.c in the
 Linux kernel through 3.15.6 allows local users to gain privileges by
 leveraging data-structure differences between an l2tp socket and an
 inet socket (bnc#887082).

 *

 CVE-2014-5077: The sctp_assoc_update function in net/sctp/associola.c
 in the Linux kernel through 3.15.8, when SCTP authentication is
 enabled, allows remote attackers to cause a denial of service (NULL
 pointer dereference and OOPS) by starting to establish an association
 between two endpoints immediately after an exchange of INIT and INIT
 ACK chunks to establish an earlier association between these
 endpoints in the opposite direction (bnc#889173).

 *

 CVE-2014-5471: Stack consumption vulnerability in the
 parse_rock_ridge_inode_internal function in fs/isofs/rock.c in the
 Linux kernel through 3.16.1 allows local users to cause a denial of
 service (uncontrolled recursion, and system crash or reboot) via a
 crafted iso9660 image with a CL entry referring to a directory entry
 that has a CL entry. (bnc#892490)

 *

 CVE-2014-5472: The parse_rock_ridge_inode_internal function in
 fs/isofs/rock.c in the Linux kernel through 3.16.1 allows local users
 to cause a denial of service (unkillable mount process) via a crafted
 iso9660 image with a self-referential CL entry. (bnc#892490)

 *

 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.2.4_04_3.0.101_0.40~0.7.3", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.2.4_04_3.0.101_0.40~0.7.3", rls:"SLES11.0SP3"))) {
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
