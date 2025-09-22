# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856722");
  script_cve_id("CVE-2023-52766", "CVE-2023-52800", "CVE-2023-52881", "CVE-2023-52917", "CVE-2023-52918", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-26758", "CVE-2024-26761", "CVE-2024-26767", "CVE-2024-26943", "CVE-2024-27026", "CVE-2024-27043", "CVE-2024-35980", "CVE-2024-36244", "CVE-2024-38576", "CVE-2024-38577", "CVE-2024-38599", "CVE-2024-41016", "CVE-2024-41031", "CVE-2024-41047", "CVE-2024-41082", "CVE-2024-42145", "CVE-2024-44932", "CVE-2024-44958", "CVE-2024-44964", "CVE-2024-45016", "CVE-2024-45025", "CVE-2024-46678", "CVE-2024-46721", "CVE-2024-46754", "CVE-2024-46766", "CVE-2024-46770", "CVE-2024-46775", "CVE-2024-46777", "CVE-2024-46797", "CVE-2024-46802", "CVE-2024-46803", "CVE-2024-46804", "CVE-2024-46805", "CVE-2024-46806", "CVE-2024-46807", "CVE-2024-46809", "CVE-2024-46810", "CVE-2024-46811", "CVE-2024-46812", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46819", "CVE-2024-46821", "CVE-2024-46825", "CVE-2024-46826", "CVE-2024-46827", "CVE-2024-46828", "CVE-2024-46830", "CVE-2024-46831", "CVE-2024-46834", "CVE-2024-46835", "CVE-2024-46836", "CVE-2024-46840", "CVE-2024-46841", "CVE-2024-46842", "CVE-2024-46843", "CVE-2024-46846", "CVE-2024-46848", "CVE-2024-46849", "CVE-2024-46851", "CVE-2024-46852", "CVE-2024-46853", "CVE-2024-46854", "CVE-2024-46855", "CVE-2024-46857", "CVE-2024-46859", "CVE-2024-46860", "CVE-2024-46861", "CVE-2024-46864", "CVE-2024-46870", "CVE-2024-46871", "CVE-2024-47658", "CVE-2024-47660", "CVE-2024-47661", "CVE-2024-47662", "CVE-2024-47663", "CVE-2024-47664", "CVE-2024-47665", "CVE-2024-47667", "CVE-2024-47668", "CVE-2024-47669", "CVE-2024-47670", "CVE-2024-47671", "CVE-2024-47672", "CVE-2024-47673", "CVE-2024-47674", "CVE-2024-47675", "CVE-2024-47681", "CVE-2024-47682", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47686", "CVE-2024-47687", "CVE-2024-47688", "CVE-2024-47692", "CVE-2024-47693", "CVE-2024-47695", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47699", "CVE-2024-47702", "CVE-2024-47704", "CVE-2024-47705", "CVE-2024-47706", "CVE-2024-47707", "CVE-2024-47709", "CVE-2024-47710", "CVE-2024-47712", "CVE-2024-47713", "CVE-2024-47714", "CVE-2024-47715", "CVE-2024-47718", "CVE-2024-47719", "CVE-2024-47720", "CVE-2024-47723", "CVE-2024-47727", "CVE-2024-47728", "CVE-2024-47730", "CVE-2024-47731", "CVE-2024-47732", "CVE-2024-47735", "CVE-2024-47737", "CVE-2024-47738", "CVE-2024-47739", "CVE-2024-47741", "CVE-2024-47742", "CVE-2024-47743", "CVE-2024-47744", "CVE-2024-47745", "CVE-2024-47747", "CVE-2024-47748", "CVE-2024-47749", "CVE-2024-47750", "CVE-2024-47751", "CVE-2024-47752", "CVE-2024-47753", "CVE-2024-47754", "CVE-2024-47756", "CVE-2024-47757", "CVE-2024-49850", "CVE-2024-49851", "CVE-2024-49852", "CVE-2024-49853", "CVE-2024-49855", "CVE-2024-49858", "CVE-2024-49860", "CVE-2024-49861", "CVE-2024-49862", "CVE-2024-49863", "CVE-2024-49864", "CVE-2024-49866", "CVE-2024-49867", "CVE-2024-49870", "CVE-2024-49871", "CVE-2024-49874", "CVE-2024-49875", "CVE-2024-49877", "CVE-2024-49878", "CVE-2024-49879", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49886", "CVE-2024-49888", "CVE-2024-49890", "CVE-2024-49891", "CVE-2024-49892", "CVE-2024-49894", "CVE-2024-49895", "CVE-2024-49896", "CVE-2024-49897", "CVE-2024-49898", "CVE-2024-49900", "CVE-2024-49901", "CVE-2024-49902", "CVE-2024-49903", "CVE-2024-49906", "CVE-2024-49907", "CVE-2024-49908", "CVE-2024-49909", "CVE-2024-49913", "CVE-2024-49914", "CVE-2024-49917", "CVE-2024-49918", "CVE-2024-49919", "CVE-2024-49920", "CVE-2024-49928", "CVE-2024-49929", "CVE-2024-49930", "CVE-2024-49931", "CVE-2024-49935", "CVE-2024-49936", "CVE-2024-49937", "CVE-2024-49938", "CVE-2024-49939", "CVE-2024-49946", "CVE-2024-49947", "CVE-2024-49949", "CVE-2024-49950", "CVE-2024-49953", "CVE-2024-49954", "CVE-2024-49955", "CVE-2024-49957", "CVE-2024-49958", "CVE-2024-49959", "CVE-2024-49960", "CVE-2024-49961", "CVE-2024-49962", "CVE-2024-49963", "CVE-2024-49965", "CVE-2024-49966", "CVE-2024-49967", "CVE-2024-49969", "CVE-2024-49972", "CVE-2024-49973", "CVE-2024-49974", "CVE-2024-49981", "CVE-2024-49982", "CVE-2024-49985", "CVE-2024-49986", "CVE-2024-49991", "CVE-2024-49993", "CVE-2024-49995", "CVE-2024-49996", "CVE-2024-50000", "CVE-2024-50001", "CVE-2024-50002", "CVE-2024-50007", "CVE-2024-50008", "CVE-2024-50013", "CVE-2024-50015", "CVE-2024-50017", "CVE-2024-50019", "CVE-2024-50020", "CVE-2024-50021", "CVE-2024-50022", "CVE-2024-50023", "CVE-2024-50024", "CVE-2024-50025", "CVE-2024-50027", "CVE-2024-50028", "CVE-2024-50031", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50040", "CVE-2024-50041", "CVE-2024-50042", "CVE-2024-50044", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50047", "CVE-2024-50048", "CVE-2024-50049", "CVE-2024-50055", "CVE-2024-50058", "CVE-2024-50059", "CVE-2024-50060", "CVE-2024-50061", "CVE-2024-50062", "CVE-2024-50063", "CVE-2024-50064", "CVE-2024-50069", "CVE-2024-50073", "CVE-2024-50074", "CVE-2024-50075", "CVE-2024-50076", "CVE-2024-50077", "CVE-2024-50078", "CVE-2024-50080", "CVE-2024-50081");
  script_tag(name:"creation_date", value:"2024-11-14 05:10:58 +0000 (Thu, 14 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3984-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243984-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232819");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019815.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:3984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-36244: net/sched: taprio: extend minimum interval restriction to entire cycle too (bsc#1226797).
- CVE-2024-41031: mm/filemap: skip to create PMD-sized page cache if needed (bsc#1228454).
- CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command (bsc#1228620).
- CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc (bsc#1230179).
- CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
- CVE-2024-45025: fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (bsc#1230456).
- CVE-2024-46678: bonding: change ipsec_lock from spin lock to mutex (bsc#1230550).
- CVE-2024-46721: pparmor: fix possible NULL pointer dereference (bsc#1230710)
- CVE-2024-46754: bpf: Remove tst_run from lwt_seg6local_prog_ops (bsc#1230801).
- CVE-2024-46766: ice: move netif_queue_set_napi to rtnl-protected sections (bsc#1230762).
- CVE-2024-46770: ice: Add netif_device_attach/detach into PF reset flow (bsc#1230763).
- CVE-2024-46775: drm/amd/display: Validate function returns (bsc#1230774).
- CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
- CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
- CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links (bsc#1231197).
- CVE-2024-46826: ELF: fix kernel.randomize_va_space double read (bsc#1231115).
- CVE-2024-46828: uprobes: fix kernel info leak via '[uprobes]' vma (bsc#1231114).
- CVE-2024-46831: net: microchip: vcap: Fix use-after-free error in kunit test (bsc#1231117).
- CVE-2024-46834: ethtool: fail closed if we can't get max channel used in indirection tables (bsc#1231096).
- CVE-2024-46840: btrfs: clean up our handling of refs == 0 in snapshot delete (bsc#1231105).
- CVE-2024-46841: btrfs: do not BUG_ON on ENOMEM from btrfs_lookup_extent_info() in walk_down_proc() (bsc#1231094).
- CVE-2024-46843: scsi: ufs: core: Remove SCSI host only if added (bsc#1231100).
- CVE-2024-46854: net: dpaa: Pad packets to ETH_ZLEN (bsc#1231084).
- CVE-2024-46855: netfilter: nft_socket: fix sk refcount leaks (bsc#1231085).
- CVE-2024-46857: net/mlx5: Fix bridge mode operations when there are no VFs (bsc#1231087).
- CVE-2024-46870: drm/amd/display: Disable DMCUB timeout for DCN35 (bsc#1231435).
- CVE-2024-47658: crypto: stm32/cryp - call finalize with bh disabled (bsc#1231436).
- CVE-2024-47660: fsnotify: clear PARENT_WATCHED flags lazily (bsc#1231439).
- CVE-2024-47664: spi: hisi-kunpeng: Add verification for the max_frequency provided by the firmware (bsc#1231442).
- CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
- CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
- CVE-2024-47685: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-livepatch-devel", rpm:"kernel-azure-livepatch-devel~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~6.4.0~150600.8.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~6.4.0~150600.8.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~6.4.0~150600.8.17.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~6.4.0~150600.8.17.2", rls:"openSUSELeap15.6"))) {
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
