# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856156");
  script_cve_id("CVE-2021-47047", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47187", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47191", "CVE-2021-47192", "CVE-2021-47193", "CVE-2021-47194", "CVE-2021-47195", "CVE-2021-47196", "CVE-2021-47197", "CVE-2021-47198", "CVE-2021-47199", "CVE-2021-47200", "CVE-2021-47201", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47206", "CVE-2021-47207", "CVE-2021-47209", "CVE-2021-47210", "CVE-2021-47211", "CVE-2021-47212", "CVE-2021-47214", "CVE-2021-47215", "CVE-2021-47216", "CVE-2021-47217", "CVE-2021-47218", "CVE-2021-47219", "CVE-2022-48631", "CVE-2022-48632", "CVE-2022-48634", "CVE-2022-48636", "CVE-2022-48637", "CVE-2022-48638", "CVE-2022-48639", "CVE-2022-48640", "CVE-2022-48642", "CVE-2022-48644", "CVE-2022-48646", "CVE-2022-48647", "CVE-2022-48648", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48652", "CVE-2022-48653", "CVE-2022-48654", "CVE-2022-48655", "CVE-2022-48656", "CVE-2022-48657", "CVE-2022-48658", "CVE-2022-48659", "CVE-2022-48660", "CVE-2022-48662", "CVE-2022-48663", "CVE-2022-48667", "CVE-2022-48668", "CVE-2022-48671", "CVE-2022-48672", "CVE-2022-48673", "CVE-2022-48675", "CVE-2022-48686", "CVE-2022-48687", "CVE-2022-48688", "CVE-2022-48690", "CVE-2022-48692", "CVE-2022-48693", "CVE-2022-48694", "CVE-2022-48695", "CVE-2022-48697", "CVE-2022-48698", "CVE-2022-48700", "CVE-2022-48701", "CVE-2022-48702", "CVE-2022-48703", "CVE-2022-48704", "CVE-2023-2860", "CVE-2023-52488", "CVE-2023-52503", "CVE-2023-52561", "CVE-2023-52585", "CVE-2023-52589", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52593", "CVE-2023-52614", "CVE-2023-52616", "CVE-2023-52620", "CVE-2023-52627", "CVE-2023-52635", "CVE-2023-52636", "CVE-2023-52645", "CVE-2023-52652", "CVE-2023-6270", "CVE-2024-0639", "CVE-2024-0841", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-23850", "CVE-2024-26601", "CVE-2024-26610", "CVE-2024-26656", "CVE-2024-26660", "CVE-2024-26671", "CVE-2024-26673", "CVE-2024-26675", "CVE-2024-26680", "CVE-2024-26681", "CVE-2024-26684", "CVE-2024-26685", "CVE-2024-26687", "CVE-2024-26688", "CVE-2024-26689", "CVE-2024-26696", "CVE-2024-26697", "CVE-2024-26702", "CVE-2024-26704", "CVE-2024-26718", "CVE-2024-26722", "CVE-2024-26727", "CVE-2024-26733", "CVE-2024-26736", "CVE-2024-26737", "CVE-2024-26739", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26745", "CVE-2024-26747", "CVE-2024-26749", "CVE-2024-26751", "CVE-2024-26754", "CVE-2024-26760", "CVE-2024-26763", "CVE-2024-26764", "CVE-2024-26766", "CVE-2024-26769", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26776", "CVE-2024-26779", "CVE-2024-26783", "CVE-2024-26787", "CVE-2024-26790", "CVE-2024-26792", "CVE-2024-26793", "CVE-2024-26798", "CVE-2024-26805", "CVE-2024-26807", "CVE-2024-26816", "CVE-2024-26817", "CVE-2024-26820", "CVE-2024-26825", "CVE-2024-26830", "CVE-2024-26833", "CVE-2024-26836", "CVE-2024-26843", "CVE-2024-26848", "CVE-2024-26852", "CVE-2024-26853", "CVE-2024-26855", "CVE-2024-26856", "CVE-2024-26857", "CVE-2024-26861", "CVE-2024-26862", "CVE-2024-26866", "CVE-2024-26872", "CVE-2024-26875", "CVE-2024-26878", "CVE-2024-26879", "CVE-2024-26881", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26885", "CVE-2024-26891", "CVE-2024-26893", "CVE-2024-26895", "CVE-2024-26896", "CVE-2024-26897", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26917", "CVE-2024-26927", "CVE-2024-26948", "CVE-2024-26950", "CVE-2024-26951", "CVE-2024-26955", "CVE-2024-26956", "CVE-2024-26960", "CVE-2024-26965", "CVE-2024-26966", "CVE-2024-26969", "CVE-2024-26970", "CVE-2024-26972", "CVE-2024-26981", "CVE-2024-26982", "CVE-2024-26993", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27030", "CVE-2024-27038", "CVE-2024-27039", "CVE-2024-27041", "CVE-2024-27043", "CVE-2024-27046", "CVE-2024-27056", "CVE-2024-27062", "CVE-2024-27389");
  script_tag(name:"creation_date", value:"2024-05-24 01:01:50 +0000 (Fri, 24 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-23 19:13:31 +0000 (Mon, 23 Dec 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1659-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1659-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241659-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219264");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223474");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223477");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223964");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:1659-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-26760: Fixed scsi/target/pscsi bio_put() for error case (bsc#1222596).
- CVE-2024-27389: Fixed pstore inode handling with d_invalidate() (bsc#1223705).
- CVE-2024-27062: Fixed nouveau lock inside client object tree (bsc#1223834).
- CVE-2024-27056: Fixed wifi/iwlwifi/mvm to ensure offloading TID queue exists (bsc#1223822).
- CVE-2024-27046: Fixed nfp/flower handling acti_netdevs allocation failure (bsc#1223827).
- CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
- CVE-2024-27041: Fixed drm/amd/display NULL checks for adev->dm.dc in amdgpu_dm_fini() (bsc#1223714).
- CVE-2024-27039: Fixed clk/hisilicon/hi3559a an erroneous devm_kfree() (bsc#1223821).
- CVE-2024-27038: Fixed clk_core_get NULL pointer dereference (bsc#1223816).
- CVE-2024-27030: Fixed octeontx2-af to use separate handlers for interrupts (bsc#1223790).
- CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS (bsc#1223735).
- CVE-2024-27013: Fixed tun limit printing rate when illegal packet received by tun device (bsc#1223745).
- CVE-2024-26993: Fixed fs/sysfs reference leak in sysfs_break_active_protection() (bsc#1223693).
- CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value of zero (bsc#1223634).
- CVE-2024-26970: Fixed clk/qcom/gcc-ipq6018 termination of frequency table arrays (bsc#1223644).
- CVE-2024-26969: Fixed clk/qcom/gcc-ipq8074 termination of frequency table arrays (bsc#1223645).
- CVE-2024-26966: Fixed clk/qcom/mmcc-apq8084 termination of frequency table arrays (bsc#1223646).
- CVE-2024-26965: Fixed clk/qcom/mmcc-msm8974 termination of frequency table arrays (bsc#1223648).
- CVE-2024-26960: Fixed mm/swap race between free_swap_and_cache() and swapoff() (bsc#1223655).
- CVE-2024-26951: Fixed wireguard/netlink check for dangling peer via is_dead instead of empty list (bsc#1223660).
- CVE-2024-26950: Fixed wireguard/netlink to access device through ctx instead of peer (bsc#1223661).
- CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in dc_state_release (bsc#1223664).
- CVE-2024-26927: Fixed ASoC/SOF bounds checking to firmware data Smatch (bsc#1223525).
- CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent kernel-infoleak (bsc#1223198).
- CVE-2024-26896: Fixed wifi/wfx memory leak when starting AP (bsc#1223042).
- CVE-2024-26893: Fixed firmware/arm_scmi for possible double free in SMC transport cleanup path (bsc#1223196).
- CVE-2024-26885: Fixed bpf DEVMAP_HASH overflow check on 32-bit arches (bsc#1223190).
- CVE-2024-26884: Fixed bpf hashtab overflow check on 32-bit arches (bsc#1223189).
- CVE-2024-26883: Fixed bpf stackmap overflow check on 32-bit arches (bsc#1223035).
- CVE-2024-26882: Fixed net/ip_tunnel to make sure to pull inner ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.62.2.150500.6.27.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.62.2.150500.6.27.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.62.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.62.2", rls:"openSUSELeap15.5"))) {
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
