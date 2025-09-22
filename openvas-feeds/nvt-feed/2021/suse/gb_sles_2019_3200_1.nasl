# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.3200.1");
  script_cve_id("CVE-2017-18595", "CVE-2019-0154", "CVE-2019-0155", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-14895", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15916", "CVE-2019-16231", "CVE-2019-16233", "CVE-2019-16995", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17666", "CVE-2019-18660", "CVE-2019-18683", "CVE-2019-18805", "CVE-2019-18809", "CVE-2019-19046", "CVE-2019-19049", "CVE-2019-19052", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19060", "CVE-2019-19062", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19078", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083", "CVE-2019-19227", "CVE-2019-9456", "CVE-2019-9506");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 21:05:12 +0000 (Mon, 16 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:3200-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:3200-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20193200-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1146664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1149976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1150933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158068");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-December/006221.html");
  script_xref(name:"URL", value:"https://www.suse.com/support/kb/doc/?id=7024251");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:3200-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-19081: Fixed a memory leak in the nfp_flower_spawn_vnic_reprs() could
 have allowed attackers to cause a denial of service (bsc#1157045).
- CVE-2019-19080: Fixed four memory leaks in the nfp_flower_spawn_phy_reprs() could
 have allowed attackers to cause a denial of service (bsc#1157044).
- CVE-2019-19052: Fixed a memory leak in the gs_can_open() which could have led
 to denial of service (bsc#1157324).
- CVE-2019-19067: Fixed multiple memory leaks in acp_hw_init (bsc#1157180).
- CVE-2019-19060: Fixed a memory leak in the adis_update_scan_mode() which could have
 led to denial of service (bsc#1157178).
- CVE-2019-19049: Fixed a memory leak in unittest_data_add (bsc#1157173).
- CVE-2019-19075: Fixed a memory leak in the ca8210_probe() which could have led to
 denial of service by triggering ca8210_get_platform_data() failures (bsc#1157162).
- CVE-2019-19058: Fixed a memory leak in the alloc_sgtable() which could have led to
 denial of service by triggering alloc_page() failures (bsc#1157145).
- CVE-2019-19074: Fixed a memory leak in the ath9k_wmi_cmd() function which could have led to
 denial of service (bsc#1157143).
- CVE-2019-19073: Fixed multiple memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c which
 could have led to denial of service by triggering wait_for_completion_timeout() failures (bsc#1157070).
- CVE-2019-19083: Fixed multiple memory leaks in *clock_source_create() functions which could have led
 to denial of service (bsc#1157049).
- CVE-2019-19082: Fixed multiple memory leaks in *create_resource_pool() which could have led to
 denial of service (bsc#1157046).
- CVE-2019-15916: Fixed a memory leak in register_queue_kobjects() which might
 have led denial of service (bsc#1149448).
- CVE-2019-0154: Fixed an improper access control in subsystem for Intel (R)
 processor graphics whichs may have allowed an authenticated user to potentially
 enable denial of service via local access (bsc#1135966).
- CVE-2019-0155: Fixed an improper access control in subsystem for Intel (R)
 processor graphics whichs may have allowed an authenticated user to potentially
 enable escalation of privilege via local access (bsc#1135967).
- CVE-2019-16231: Fixed a NULL pointer dereference due to lack of checking the
 alloc_workqueue return value (bsc#1150466).
- CVE-2019-18805: Fixed an integer overflow in tcp_ack_update_rtt() leading to
 a denial of service or possibly unspecified other impact (bsc#1156187).
- CVE-2019-17055: Enforced CAP_NET_RAW in the AF_ISDN network module to restrict
 unprivileged users to create a raw socket (bsc#1152782).
- CVE-2019-16995: Fixed a memory leak in hsr_dev_finalize() which may have caused
 denial of service (bsc#1152685).
- CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.7.1", rls:"SLES12.0SP5"))) {
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
