# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20220.1");
  script_cve_id("CVE-2025-38704", "CVE-2025-39880", "CVE-2025-39977", "CVE-2025-40042", "CVE-2025-40123", "CVE-2025-40130", "CVE-2025-40160", "CVE-2025-40167", "CVE-2025-40170", "CVE-2025-40179", "CVE-2025-40190", "CVE-2025-40209", "CVE-2025-40211", "CVE-2025-40212", "CVE-2025-40213", "CVE-2025-40214", "CVE-2025-40215", "CVE-2025-40218", "CVE-2025-40219", "CVE-2025-40220", "CVE-2025-40221", "CVE-2025-40223", "CVE-2025-40225", "CVE-2025-40226", "CVE-2025-40231", "CVE-2025-40233", "CVE-2025-40235", "CVE-2025-40237", "CVE-2025-40238", "CVE-2025-40239", "CVE-2025-40240", "CVE-2025-40242", "CVE-2025-40246", "CVE-2025-40248", "CVE-2025-40250", "CVE-2025-40251", "CVE-2025-40252", "CVE-2025-40254", "CVE-2025-40255", "CVE-2025-40256", "CVE-2025-40258", "CVE-2025-40262", "CVE-2025-40263", "CVE-2025-40264", "CVE-2025-40266", "CVE-2025-40268", "CVE-2025-40269", "CVE-2025-40271", "CVE-2025-40272", "CVE-2025-40273", "CVE-2025-40274", "CVE-2025-40275", "CVE-2025-40276", "CVE-2025-40277", "CVE-2025-40278", "CVE-2025-40279", "CVE-2025-40280", "CVE-2025-40282", "CVE-2025-40283", "CVE-2025-40284", "CVE-2025-40287", "CVE-2025-40288", "CVE-2025-40289", "CVE-2025-40292", "CVE-2025-40293", "CVE-2025-40294", "CVE-2025-40297", "CVE-2025-40301", "CVE-2025-40302", "CVE-2025-40303", "CVE-2025-40304", "CVE-2025-40307", "CVE-2025-40308", "CVE-2025-40309", "CVE-2025-40310", "CVE-2025-40311", "CVE-2025-40314", "CVE-2025-40315", "CVE-2025-40316", "CVE-2025-40317", "CVE-2025-40318", "CVE-2025-40319", "CVE-2025-40320", "CVE-2025-40321", "CVE-2025-40322", "CVE-2025-40323", "CVE-2025-40324", "CVE-2025-40328", "CVE-2025-40329", "CVE-2025-40330", "CVE-2025-40331", "CVE-2025-40332", "CVE-2025-40337", "CVE-2025-40338", "CVE-2025-40339", "CVE-2025-40340", "CVE-2025-40342", "CVE-2025-40343", "CVE-2025-40344", "CVE-2025-40345", "CVE-2025-40346", "CVE-2025-40347", "CVE-2025-40350", "CVE-2025-40353", "CVE-2025-40354", "CVE-2025-40355", "CVE-2025-40357", "CVE-2025-40359", "CVE-2025-40360", "CVE-2025-40362", "CVE-2025-68167", "CVE-2025-68170", "CVE-2025-68171", "CVE-2025-68172", "CVE-2025-68176", "CVE-2025-68180", "CVE-2025-68181", "CVE-2025-68183", "CVE-2025-68184", "CVE-2025-68185", "CVE-2025-68190", "CVE-2025-68192", "CVE-2025-68194", "CVE-2025-68195", "CVE-2025-68197", "CVE-2025-68198", "CVE-2025-68201", "CVE-2025-68202", "CVE-2025-68206", "CVE-2025-68207", "CVE-2025-68208", "CVE-2025-68209", "CVE-2025-68210", "CVE-2025-68213", "CVE-2025-68215", "CVE-2025-68217", "CVE-2025-68222", "CVE-2025-68223", "CVE-2025-68230", "CVE-2025-68233", "CVE-2025-68235", "CVE-2025-68237", "CVE-2025-68238", "CVE-2025-68239", "CVE-2025-68242", "CVE-2025-68244", "CVE-2025-68249", "CVE-2025-68252", "CVE-2025-68254", "CVE-2025-68255", "CVE-2025-68256", "CVE-2025-68257", "CVE-2025-68258", "CVE-2025-68259", "CVE-2025-68264", "CVE-2025-68283", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68286", "CVE-2025-68287", "CVE-2025-68289", "CVE-2025-68290", "CVE-2025-68293", "CVE-2025-68298", "CVE-2025-68301", "CVE-2025-68302", "CVE-2025-68303", "CVE-2025-68305", "CVE-2025-68306", "CVE-2025-68307", "CVE-2025-68308", "CVE-2025-68311", "CVE-2025-68312", "CVE-2025-68313", "CVE-2025-68317", "CVE-2025-68327", "CVE-2025-68328", "CVE-2025-68330", "CVE-2025-68331", "CVE-2025-68332", "CVE-2025-68335", "CVE-2025-68339", "CVE-2025-68340", "CVE-2025-68342", "CVE-2025-68343", "CVE-2025-68344", "CVE-2025-68345", "CVE-2025-68346", "CVE-2025-68347", "CVE-2025-68351", "CVE-2025-68352", "CVE-2025-68353", "CVE-2025-68354", "CVE-2025-68362", "CVE-2025-68363", "CVE-2025-68378", "CVE-2025-68380", "CVE-2025-68724", "CVE-2025-68732", "CVE-2025-68736", "CVE-2025-68740", "CVE-2025-68742", "CVE-2025-68744", "CVE-2025-68746", "CVE-2025-68747", "CVE-2025-68748", "CVE-2025-68749", "CVE-2025-68750", "CVE-2025-68753", "CVE-2025-68757", "CVE-2025-68758", "CVE-2025-68759", "CVE-2025-68765", "CVE-2025-68766", "CVE-2025-71096");
  script_tag(name:"creation_date", value:"2026-02-09 04:44:52 +0000 (Mon, 09 Feb 2026)");
  script_version("2026-02-09T06:03:20+0000");
  script_tag(name:"last_modification", value:"2026-02-09 06:03:20 +0000 (Mon, 09 Feb 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-20 20:27:54 +0000 (Tue, 20 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20220-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20220-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620220-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254828");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255233");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255252");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256794");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024067.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:20220-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 16.0 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2025-38704: rcu/nocb: Fix possible invalid rdp's->nocb_cb_kthread pointer (bsc#1254408).
- CVE-2025-39880: ceph: fix race condition validating r_parent before applying state (bsc#1250388).
- CVE-2025-39977: futex: Prevent use-after-free during requeue-PI (bsc#1252046).
- CVE-2025-40042: tracing: Fix race condition in kprobe initialization causing NULL pointer dereference (bsc#1252861).
- CVE-2025-40123: bpf: Enforce expected_attach_type for tailcall compatibility (bsc#1253365).
- CVE-2025-40130: scsi: ufs: core: Fix data race in CPU latency PM QoS request handling
- CVE-2025-40160: xen/events: Cleanup find_virq() return codes (bsc#1253400).
- CVE-2025-40167: ext4: detect invalid INLINE_DATA + EXTENTS flag combination (bsc#1253458).
- CVE-2025-40170: net: use dst_dev_rcu() in sk_setup_caps() (bsc#1253413).
- CVE-2025-40179: ext4: verify orphan file size is not too big (bsc#1253442).
- CVE-2025-40190: ext4: guard against EA inode refcount underflow in xattr update (bsc#1253623).
- CVE-2025-40214: af_unix: Initialise scc_index in unix_add_edge() (bsc#1254961).
- CVE-2025-40215: xfrm: delete x->tunnel as we delete x (bsc#1254959).
- CVE-2025-40218: mm/damon/vaddr: do not repeat pte_offset_map_lock() until success (bsc#1254964).
- CVE-2025-40220: fuse: fix livelock in synchronous file put from fuseblk workers (bsc#1254520).
- CVE-2025-40231: vsock: fix lock inversion in vsock_assign_transport() (bsc#1254815).
- CVE-2025-40233: ocfs2: clear extent cache after moving/defragmenting extents (bsc#1254813).
- CVE-2025-40237: fs/notify: call exportfs_encode_fid with s_umount (bsc#1254809).
- CVE-2025-40238: net/mlx5: Fix IPsec cleanup over MPV device (bsc#1254871).
- CVE-2025-40239: net: phy: micrel: always set shared->phydev for LAN8814 (bsc#1254868).
- CVE-2025-40242: gfs2: Fix unlikely race in gdlm_put_lock (bsc#1255075).
- CVE-2025-40246: xfs: fix out of bounds memory read error in symlink repair (bsc#1254861).
- CVE-2025-40248: vsock: Ignore signal/timeout on connect() if already established (bsc#1254864).
- CVE-2025-40250: net/mlx5: Clean up only new IRQ glue on request_irq() failure (bsc#1254854).
- CVE-2025-40251: devlink: rate: Unset parent pointer in devl_rate_nodes_destroy (bsc#1254856).
- CVE-2025-40252: net: qlogic/qede: fix potential out-of-bounds read in
 qede_tpa_cont() and qede_tpa_end() (bsc#1254849).
- CVE-2025-40254: net: openvswitch: remove never-working support for setting nsh fields (bsc#1254852).
- CVE-2025-40255: net: core: prevent NULL deref in generic_hwtstamp_ioctl_lower() (bsc#1255156).
- CVE-2025-40258: mptcp: fix race condition in mptcp_schedule_work() (bsc#1254843).
- CVE-2025-40264: be2net: pass wrb_params in case of OS2BMC (bsc#1254835).
- CVE-2025-40268: cifs: client: fix memory leak in smb3_fs_context_parse_param ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.12.0~160000.9.1.160000.2.6", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.12.0~160000.9.1", rls:"SLES16.0.0"))) {
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
