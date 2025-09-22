# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0652.1");
  script_cve_id("CVE-2010-1173", "CVE-2010-1641", "CVE-2010-2066", "CVE-2010-2478", "CVE-2010-2495", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2798", "CVE-2010-2803", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-2946", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2959", "CVE-2010-2960", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3015", "CVE-2010-3078", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3084", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3310", "CVE-2010-3437", "CVE-2010-3699", "CVE-2010-3705", "CVE-2010-3858", "CVE-2010-3861", "CVE-2010-3865", "CVE-2010-3873", "CVE-2010-3874", "CVE-2010-3875", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-3880", "CVE-2010-3881", "CVE-2010-3904", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4076", "CVE-2010-4077", "CVE-2010-4082", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162", "CVE-2010-4163", "CVE-2010-4164", "CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4175", "CVE-2010-4243", "CVE-2010-4251", "CVE-2010-4258", "CVE-2010-4342", "CVE-2010-4346", "CVE-2010-4526", "CVE-2010-4527", "CVE-2010-4529", "CVE-2010-4650", "CVE-2010-4656", "CVE-2010-4668", "CVE-2010-5313", "CVE-2011-0006", "CVE-2011-0191", "CVE-2011-0521", "CVE-2011-0710", "CVE-2011-0711", "CVE-2011-0712", "CVE-2011-1012", "CVE-2011-1013", "CVE-2011-1016", "CVE-2011-1017", "CVE-2011-1020", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1082", "CVE-2011-1083", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1163", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1173", "CVE-2011-1180", "CVE-2011-1182", "CVE-2011-1476", "CVE-2011-1477", "CVE-2011-1478", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1593", "CVE-2011-1598", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1748", "CVE-2011-1833", "CVE-2011-2182", "CVE-2011-2183", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2491", "CVE-2011-2494", "CVE-2011-2496", "CVE-2011-2517", "CVE-2011-2699", "CVE-2011-3188", "CVE-2011-3593", "CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4086", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4132", "CVE-2011-4326", "CVE-2011-4330", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0879", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1601", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2745", "CVE-2012-3375", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511", "CVE-2012-4444", "CVE-2012-4530", "CVE-2012-4565", "CVE-2012-6537", "CVE-2012-6538", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6548", "CVE-2012-6549", "CVE-2012-6647", "CVE-2012-6657", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0310", "CVE-2013-0343", "CVE-2013-0349", "CVE-2013-0871", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1827", "CVE-2013-1860", "CVE-2013-1928", "CVE-2013-1943", "CVE-2013-2015", "CVE-2013-2141", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2634", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2929", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-4162", "CVE-2013-4299", "CVE-2013-4345", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4587", "CVE-2013-4588", "CVE-2013-4591", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6378", "CVE-2013-6382", "CVE-2013-6383", "CVE-2013-6885", "CVE-2013-7027", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7267", "CVE-2013-7268", "CVE-2013-7269", "CVE-2013-7270", "CVE-2013-7271", "CVE-2013-7339", "CVE-2014-0101", "CVE-2014-0181", "CVE-2014-0196", "CVE-2014-0203", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1874", "CVE-2014-2523", "CVE-2014-2678", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3917", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5077", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-8133", "CVE-2014-8160", "CVE-2014-8709", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9420", "CVE-2014-9584", "CVE-2014-9585");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-03-24 13:44:43 +0000 (Mon, 24 Mar 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0652-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150652-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/466279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/468397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/501563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/529535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/552250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/557710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/558740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/564324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/564423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/566768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/573330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/574006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/577967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/578572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/580373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/582730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/584493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/585385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/588929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/594362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/595215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/596113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/596646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/598308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/598493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/598677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/599508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/599671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/600043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/600256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/600375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/600579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/601520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/602150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/602232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/602838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/602969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/603738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/605001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/605321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/605947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/606575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/606743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/606778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/606797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/607123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/607448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/607628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/607890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/608435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/608478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/608576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/609172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/609196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/609281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/609506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/610362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/610598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/610783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/610828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/611094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/611104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/611760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/612009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/612457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/612729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/613171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/613273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/613330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/613542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/613906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/614226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/614332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/614793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/615003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/615557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/615630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/616080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/616088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/616369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/616464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/616612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/617248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/617464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/618767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/619840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/620929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/621111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/621598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/621715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/622597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/622635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/622727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/622868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/623307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/623393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/623472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/624850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/625167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/625666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/625674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/625965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/626119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/626321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/626880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/627060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/627386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/627447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/627518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/628180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/628604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/630068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/630121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/630132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/630970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/631075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/631801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/632309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/632317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/632568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/632974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/632975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/633733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/634637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/635413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/635425");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/635515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/636850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/637944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/638985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/639944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/640276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/640278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/640721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/640850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/640878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/641105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/641247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/641811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/642486");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/643922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/644219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/644350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/644373");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/644630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/645659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/646045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/646226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/646542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/646702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/646908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/647392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/647497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/647567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/647775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/648112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/648308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/648647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/648701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/648916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/649820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/650748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/652945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/653930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/654967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/655027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/655220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/655278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/655964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/655973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/656219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/656471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/656587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/658829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/659101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/659144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/659394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/659419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/660507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/660546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/661605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/661945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/662945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/663706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/664149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/664463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/665480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/665499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/665524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/665663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/666893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/667226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/667766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/668929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/669058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/669571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/669889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/671943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/672524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/673516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/673934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/674982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/675115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/675127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/675963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/676602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/677783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/678466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/678728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/679545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/679588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/679812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/680040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/680845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/681826");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/68199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/682965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/683107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/683282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/683569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/685226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/685276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/686980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/687789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/688326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/688432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/688685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/688996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/689797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/690683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/692343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/692454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/692459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/692460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/692502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/694863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/694945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/695898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/696107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/696586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/697181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/697901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/697920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/698604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/699709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/699946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/700401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/700879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/701170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/701183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/701622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/701977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/702013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/702285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/706374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/706973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/707288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/708625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/709671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/711378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/711501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/711539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/712002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/712404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/712405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/713229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/713650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/714744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/714906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/715250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/716023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/717263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/717690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/717884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/719450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/719786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/719916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/720536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/721299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/721337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/721464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/721830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/721840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/722429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/722504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/722910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/723542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/723815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/724365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/724734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/724800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/724989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/725453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/725502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/725709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/725878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/726600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/726788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/728339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/728626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/729111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/729721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/729854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/730118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/731981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/732021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/732296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/732535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/732677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/733146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/733863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/734056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/734300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/735216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/735347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/735446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/735453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/735635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/736018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/736813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/738210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/738400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/740535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/740703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/740867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/740969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/742270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/743870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/744955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/745640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/745832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/745929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/748812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/748896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/749569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/750079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/752544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/752972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/754898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/760596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/761774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/762099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/762366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/763463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/763654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/767610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/767612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/768668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/769644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/769896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/770695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/772849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/773831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/774523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/775182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/776024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/776144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/776885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/780004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/780008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/780572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/782178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/785016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/786013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/787573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/787576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/794824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/795354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/797175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/798050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/800280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/801178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/803320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/804154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/804653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/805945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/806980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/807320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/808827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/809903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/810045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/810473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/811354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/812364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/814716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/817377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/818371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/823618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/825227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/833820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/835839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/840858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/845028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/846404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/851103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/853052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/874108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/875798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/876102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/877257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/884530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/885725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/896779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/902351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/910251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915826");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001322.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Kernel' package(s) announced via the SUSE-SU-2015:0652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP1 Teradata kernel was updated to fix bugs
and security issues.

Following security issues were fixed:

CVE-2011-1083: Limit the path length users can build using epoll() to avoid
local attackers consuming lots of kernel CPU time.

CVE-2011-4086: Fixed a oops in jbd/jbd2 that could be caused by specific
filesystem access patterns.

CVE-2011-4622: KVM: Prevent starting PIT timers in the absence of irqchip
support.

CVE-2012-0045: KVM: Extend 'struct x86_emulate_ops' with 'get_cpuid' and
fix missing checks in syscall emulation.

CVE-2012-0879: Fix io_context leak after clone with CLONE_IO.

CVE-2012-1090: Fixed a dentry refcount leak in the CIFS file system that
could lead to a crash on unmount.

CVE-2012-1097: The regset common infrastructure assumed that regsets would
always have .get and .set methods, but necessarily .active methods.
Unfortunately people have since written regsets without .set method, so
NULL pointer dereference attacks were possible.

Following non-security issues were fixed:

 * SCSI inquiry doesn't return data on SLES 11-SP1 Xen VMs (bnc#745929).
 * FC transport driver killing off the timers/work queues (bnc#734300).
 * The driver ixgbevf doesn't work on newer SLES 11-SP1 kernels
 (bnc#752972).
 * Pack sparsemem memmap sections closer together and in higher zones
 (bnc#743870).

Following feature was implemented:

 * The megaraid_sas driver update to version 5.40-LSI (bnc#736813).

Security Issues:

 * CVE-2011-1083
 <[link moved to references]>
 * CVE-2011-4086
 <[link moved to references]>
 * CVE-2011-4622
 <[link moved to references]>
 * CVE-2012-0045
 <[link moved to references]>
 * CVE-2012-0879
 <[link moved to references]>
 * CVE-2012-1090
 <[link moved to references]>
 * CVE-2012-1097
 <[link moved to references]>");

  script_tag(name:"affected", value:"'Kernel' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-default", rpm:"btrfs-kmp-default~0_2.6.32.54_0.3~0.3.73", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-pae", rpm:"btrfs-kmp-pae~0_2.6.32.59_0.13~0.3.163", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-xen", rpm:"btrfs-kmp-xen~0_2.6.32.54_0.3~0.3.73", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.32.59_0.13~7.9.130", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-trace", rpm:"ext4dev-kmp-trace~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.32.54_0.3~7.9.40", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-default", rpm:"hyper-v-kmp-default~0_2.6.32.54_0.3~0.18.3", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-pae", rpm:"hyper-v-kmp-pae~0_2.6.32.59_0.13~0.18.39", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-trace", rpm:"hyper-v-kmp-trace~0_2.6.32.54_0.3~0.18.3", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.54~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.54~0.5.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.15.2", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.54~0.7.TDC.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_16_2.6.32.59_0.15~0.5.26", rls:"SLES11.0SP1"))) {
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
