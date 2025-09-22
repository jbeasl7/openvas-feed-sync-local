# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0222.1");
  script_cve_id("CVE-2017-5753", "CVE-2018-12232", "CVE-2018-14625", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-18281", "CVE-2018-18397", "CVE-2018-19407", "CVE-2018-19824", "CVE-2018-19854", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-9568");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-30 17:21:29 +0000 (Wed, 30 Jan 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0222-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0222-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190222-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120633");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122292");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-February/005074.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0222-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel for Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-19407: The vcpu_scan_ioapic function in arch/x86/kvm/x86.c allowed local users to cause a denial of service (NULL pointer dereference and BUG) via crafted system calls that reach a situation where ioapic was uninitialized (bnc#1116841).
- CVE-2018-16884: NFS41+ shares mounted in different network namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out (bnc#1119946).
- CVE-2018-20169: The USB subsystem mishandled size checks during the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c (bnc#1119714).
- CVE-2018-9568: In sk_clone_lock of sock.c, there is a possible memory corruption due to type confusion. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation (bnc#1118319).
- CVE-2018-16862: A security flaw was found in the way that the cleancache subsystem clears an inode after the final file truncation (removal). The new file created with the same inode may contain leftover pages from cleancache and the old file data instead of the new one (bnc#1117186).
- CVE-2018-14625: A flaw was found where an attacker may be able to have an uncontrolled read to kernel-memory from within a vm guest. A race condition between connect() and close() function may allow an attacker using the AF_VSOCK protocol to gather a 4 byte information leak or possibly intercept or corrupt AF_VSOCK messages destined to other clients (bnc#1106615).
- CVE-2018-19985: The function hso_probe read if_num from the USB device (as an u8) and used it without a length check to index an array, resulting in an OOB memory read in hso_probe or hso_get_config_data that could be used by local attackers (bnc#1120743).
- CVE-2018-12232: In net/socket.c there is a race condition between fchownat and close in cases where they target the same socket file descriptor, related to the sock_close and sockfs_setattr functions. fchownat did not increment the file descriptor reference count, which allowed close to set the socket to NULL during fchownat's execution, leading to a NULL pointer dereference and system crash (bnc#1097593).
- CVE-2018-18397: The userfaultfd implementation mishandled access control for certain UFFDIO_ ioctl calls, as demonstrated by allowing local users to write data into holes in a tmpfs file (if the user has read-only access to that file, and that file contains holes), related to fs/userfaultfd.c and mm/userfaultfd.c (bnc#1117656).
- CVE-2018-19854: An issue was discovered in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.6.2", rls:"SLES12.0SP4"))) {
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
