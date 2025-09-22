# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856720");
  script_cve_id("CVE-2021-47416", "CVE-2021-47534", "CVE-2022-3435", "CVE-2022-45934", "CVE-2022-48664", "CVE-2022-48879", "CVE-2022-48946", "CVE-2022-48947", "CVE-2022-48948", "CVE-2022-48949", "CVE-2022-48951", "CVE-2022-48953", "CVE-2022-48954", "CVE-2022-48955", "CVE-2022-48956", "CVE-2022-48957", "CVE-2022-48958", "CVE-2022-48959", "CVE-2022-48960", "CVE-2022-48961", "CVE-2022-48962", "CVE-2022-48966", "CVE-2022-48967", "CVE-2022-48968", "CVE-2022-48969", "CVE-2022-48970", "CVE-2022-48971", "CVE-2022-48972", "CVE-2022-48973", "CVE-2022-48975", "CVE-2022-48977", "CVE-2022-48978", "CVE-2022-48980", "CVE-2022-48981", "CVE-2022-48985", "CVE-2022-48987", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48992", "CVE-2022-48994", "CVE-2022-48995", "CVE-2022-48997", "CVE-2022-48999", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49003", "CVE-2022-49005", "CVE-2022-49006", "CVE-2022-49007", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49012", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49016", "CVE-2022-49017", "CVE-2022-49019", "CVE-2022-49020", "CVE-2022-49021", "CVE-2022-49022", "CVE-2022-49023", "CVE-2022-49024", "CVE-2022-49025", "CVE-2022-49026", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49029", "CVE-2022-49031", "CVE-2022-49032", "CVE-2023-2166", "CVE-2023-28327", "CVE-2023-52766", "CVE-2023-52800", "CVE-2023-52881", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-27043", "CVE-2024-36244", "CVE-2024-36957", "CVE-2024-39476", "CVE-2024-40965", "CVE-2024-42145", "CVE-2024-42226", "CVE-2024-42253", "CVE-2024-44931", "CVE-2024-44947", "CVE-2024-44958", "CVE-2024-45016", "CVE-2024-45025", "CVE-2024-46678", "CVE-2024-46716", "CVE-2024-46719", "CVE-2024-46754", "CVE-2024-46770", "CVE-2024-46775", "CVE-2024-46777", "CVE-2024-46809", "CVE-2024-46811", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46817", "CVE-2024-46818", "CVE-2024-46826", "CVE-2024-46828", "CVE-2024-46834", "CVE-2024-46840", "CVE-2024-46841", "CVE-2024-46848", "CVE-2024-46849", "CVE-2024-46854", "CVE-2024-46855", "CVE-2024-46857", "CVE-2024-47660", "CVE-2024-47661", "CVE-2024-47664", "CVE-2024-47668", "CVE-2024-47672", "CVE-2024-47673", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47692", "CVE-2024-47704", "CVE-2024-47705", "CVE-2024-47706", "CVE-2024-47707", "CVE-2024-47710", "CVE-2024-47720", "CVE-2024-47727", "CVE-2024-47730", "CVE-2024-47738", "CVE-2024-47739", "CVE-2024-47745", "CVE-2024-47747", "CVE-2024-47748", "CVE-2024-49858", "CVE-2024-49860", "CVE-2024-49866", "CVE-2024-49867", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49886", "CVE-2024-49890", "CVE-2024-49892", "CVE-2024-49894", "CVE-2024-49895", "CVE-2024-49896", "CVE-2024-49897", "CVE-2024-49899", "CVE-2024-49901", "CVE-2024-49906", "CVE-2024-49908", "CVE-2024-49909", "CVE-2024-49911", "CVE-2024-49912", "CVE-2024-49913", "CVE-2024-49914", "CVE-2024-49917", "CVE-2024-49918", "CVE-2024-49919", "CVE-2024-49920", "CVE-2024-49922", "CVE-2024-49923", "CVE-2024-49929", "CVE-2024-49930", "CVE-2024-49933", "CVE-2024-49936", "CVE-2024-49939", "CVE-2024-49946", "CVE-2024-49949", "CVE-2024-49954", "CVE-2024-49955", "CVE-2024-49958", "CVE-2024-49959", "CVE-2024-49960", "CVE-2024-49962", "CVE-2024-49967", "CVE-2024-49969", "CVE-2024-49973", "CVE-2024-49974", "CVE-2024-49975", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49993", "CVE-2024-49995", "CVE-2024-49996", "CVE-2024-50000", "CVE-2024-50001", "CVE-2024-50002", "CVE-2024-50006", "CVE-2024-50014", "CVE-2024-50019", "CVE-2024-50024", "CVE-2024-50028", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50041", "CVE-2024-50045", "CVE-2024-50046", "CVE-2024-50047", "CVE-2024-50048", "CVE-2024-50049", "CVE-2024-50055", "CVE-2024-50058", "CVE-2024-50059", "CVE-2024-50061", "CVE-2024-50063", "CVE-2024-50081");
  script_tag(name:"creation_date", value:"2024-11-14 05:00:27 +0000 (Thu, 14 Nov 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:3985-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3985-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243985-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232352");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232757");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-November/019814.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:3985-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).
- CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
- CVE-2022-48957: dpaa2-switch: Fix memory leak in dpaa2_switch_acl_entry_add() and dpaa2_switch_acl_entry_remove() (bsc#1231973).
- CVE-2022-48958: ethernet: aeroflex: fix potential skb leak in greth_init_rings() (bsc#1231889).
- CVE-2022-48959: net: dsa: sja1105: fix memory leak in sja1105_setup_devlink_regions() (bsc#1231976).
- CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
- CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
- CVE-2022-48966: net: mvneta: Fix an out of bounds check (bsc#1232191).
- CVE-2022-48980: net: dsa: sja1105: avoid out of bounds access in sja1105_init_l2_policing() (bsc#1232233).
- CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow anon_vma (bsc#1232070).
- CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
- CVE-2022-49017: tipc: re-fetch skb cb after tipc_msg_validate (bsc#1232004).
- CVE-2022-49020: net/9p: Fix a potential socket leak in p9_socket_open (bsc#1232175).
- CVE-2024-36244: net/sched: taprio: extend minimum interval restriction to entire cycle too (bsc#1226797).
- CVE-2024-36957: octeontx2-af: avoid off-by-one read from userspace (bsc#1225762).
- CVE-2024-39476: md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING (bsc#1227437).
- CVE-2024-40965: i2c: lpi2c: Avoid calling clk_get_rate during transfer (bsc#1227885).
- CVE-2024-42226: Prevent potential failure in handle_tx_event() for Transfer events without TRB (bsc#1228709).
- CVE-2024-42253: gpio: pca953x: fix pca953x_irq_bus_sync_unlock race (bsc#1229005).
- CVE-2024-44931: gpio: prevent potential speculation leaks in gpio_device_get_desc() (bsc#1229837).
- CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc (bsc#1230179).
- CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
- CVE-2024-45025: fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (bsc#1230456).
- CVE-2024-46678: bonding: change ipsec_lock from spin lock to mutex (bsc#1230550).
- CVE-2024-46716: dmaengine: altera-msgdma: properly free descriptor in msgdma_free_descriptor (bsc#1230715).
- CVE-2024-46754: bpf: Remove tst_run from lwt_seg6local_prog_ops (bsc#1230801).
- CVE-2024-46770: ice: Add netif_device_attach/detach into PF reset flow (bsc#1230763).
- CVE-2024-46775: drm/amd/display: Validate function returns (bsc#1230774).
- CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
- CVE-2024-46809: drm/amd/display: Check BIOS images before it is used (bsc#1231148).
- CVE-2024-46811: drm/amd/display: Fix ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-livepatch-devel", rpm:"kernel-rt_debug-livepatch-devel~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.76.1", rls:"openSUSELeap15.5"))) {
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
