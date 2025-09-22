# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1870.1");
  script_cve_id("CVE-2019-25160", "CVE-2020-36312", "CVE-2021-23134", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46907", "CVE-2021-46909", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46941", "CVE-2021-46950", "CVE-2021-46958", "CVE-2021-46960", "CVE-2021-46963", "CVE-2021-46964", "CVE-2021-46966", "CVE-2021-46975", "CVE-2021-46981", "CVE-2021-46988", "CVE-2021-46990", "CVE-2021-46998", "CVE-2021-47006", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47034", "CVE-2021-47045", "CVE-2021-47049", "CVE-2021-47055", "CVE-2021-47056", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47068", "CVE-2021-47070", "CVE-2021-47071", "CVE-2021-47073", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47104", "CVE-2021-47110", "CVE-2021-47112", "CVE-2021-47114", "CVE-2021-47117", "CVE-2021-47118", "CVE-2021-47119", "CVE-2021-47138", "CVE-2021-47141", "CVE-2021-47142", "CVE-2021-47143", "CVE-2021-47146", "CVE-2021-47149", "CVE-2021-47150", "CVE-2021-47153", "CVE-2021-47159", "CVE-2021-47161", "CVE-2021-47162", "CVE-2021-47165", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47169", "CVE-2021-47171", "CVE-2021-47173", "CVE-2021-47177", "CVE-2021-47179", "CVE-2021-47180", "CVE-2021-47181", "CVE-2021-47182", "CVE-2021-47183", "CVE-2021-47184", "CVE-2021-47185", "CVE-2021-47188", "CVE-2021-47189", "CVE-2021-47198", "CVE-2021-47202", "CVE-2021-47203", "CVE-2021-47204", "CVE-2021-47205", "CVE-2021-47207", "CVE-2021-47211", "CVE-2021-47216", "CVE-2021-47217", "CVE-2022-0487", "CVE-2022-48619", "CVE-2022-48626", "CVE-2022-48636", "CVE-2022-48650", "CVE-2022-48651", "CVE-2022-48667", "CVE-2022-48668", "CVE-2022-48687", "CVE-2022-48688", "CVE-2022-48695", "CVE-2022-48701", "CVE-2023-0160", "CVE-2023-28746", "CVE-2023-35827", "CVE-2023-52454", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52486", "CVE-2023-52488", "CVE-2023-52509", "CVE-2023-52515", "CVE-2023-52524", "CVE-2023-52528", "CVE-2023-52575", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52590", "CVE-2023-52591", "CVE-2023-52595", "CVE-2023-52598", "CVE-2023-52607", "CVE-2023-52614", "CVE-2023-52620", "CVE-2023-52628", "CVE-2023-52635", "CVE-2023-52639", "CVE-2023-52644", "CVE-2023-52646", "CVE-2023-52650", "CVE-2023-52652", "CVE-2023-52653", "CVE-2023-6270", "CVE-2023-6356", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-7042", "CVE-2023-7192", "CVE-2024-2201", "CVE-2024-22099", "CVE-2024-23307", "CVE-2024-23848", "CVE-2024-24855", "CVE-2024-24861", "CVE-2024-26614", "CVE-2024-26642", "CVE-2024-26651", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26689", "CVE-2024-26704", "CVE-2024-26733", "CVE-2024-26739", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26747", "CVE-2024-26754", "CVE-2024-26763", "CVE-2024-26771", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26777", "CVE-2024-26778", "CVE-2024-26779", "CVE-2024-26793", "CVE-2024-26805", "CVE-2024-26816", "CVE-2024-26817", "CVE-2024-26839", "CVE-2024-26840", "CVE-2024-26852", "CVE-2024-26855", "CVE-2024-26857", "CVE-2024-26859", "CVE-2024-26878", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26898", "CVE-2024-26901", "CVE-2024-26903", "CVE-2024-26907", "CVE-2024-26922", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-26931", "CVE-2024-26948", "CVE-2024-26993", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27043", "CVE-2024-27046", "CVE-2024-27054", "CVE-2024-27072", "CVE-2024-27073", "CVE-2024-27074", "CVE-2024-27075", "CVE-2024-27078", "CVE-2024-27388");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-23 19:13:31 +0000 (Mon, 23 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1870-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1870-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241870-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218479");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223513");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224785");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035427.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:1870-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2019-25160: Fixed out-of-bounds memory accesses in netlabel (bsc#1220394).
- CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a kvm_io_bus_unregister_dev memory leak upon a kmalloc failure (bsc#1184509).
- CVE-2021-23134: Fixed a use-after-free issue in nfc sockets (bsc#1186060).
- CVE-2021-46904: Fixed NULL pointer dereference during tty device unregistration (bsc#1220416).
- CVE-2021-46905: Fixed NULL pointer dereference on disconnect regression (bsc#1220418).
- CVE-2021-46909: Fixed PCI interrupt mapping in ARM footbridge (bsc#1220442).
- CVE-2021-46938: Fixed double free of blk_mq_tag_set in dev remove after table load fails (bsc#1220554).
- CVE-2021-46939: Fixed possible hung in trace_clock_global() (bsc#1220580).
- CVE-2021-46941: Fixed core softreset when switch mode in usb dwc3 (bsc#1220628).
- CVE-2021-46950: Fixed possible data corruption in md/raid1 when ending a failed write request (bsc#1220662).
- CVE-2021-46958: Fixed race between transaction aborts and fsyncs that could lead to use-after-free in btrfs (bsc#1220521).
- CVE-2021-46960: Fixed wrong error code from smb2_get_enc_key() (bsc#1220528).
- CVE-2021-46963: Fixed crash in qla2xxx_mqueuecommand() (bsc#1220536).
- CVE-2021-46964: Fixed unreserved extra IRQ vectors in qla2xxx (bsc#1220538).
- CVE-2021-46966: Fixed potential use-after-free issue in cm_write() (bsc#1220572).
- CVE-2021-46981: Fixed NULL pointer in flush_workqueue (bsc#1220611).
- CVE-2021-46988: Fixed possible crash in userfaultfd due to unreleased page (bsc#1220706).
- CVE-2021-46990: Fixed crashes when toggling entry flush barrier in powerpc/64s (bsc#1220743).
- CVE-2021-46998: Fixed a use after free bug in enic_hard_start_xmit() (bsc#1220625).
- CVE-2021-47006: Fixed wrong check in overflow_handler hook in ARM 9064/1 hw_breakpoint (bsc#1220751).
- CVE-2021-47015: Fixed RX consumer index logic in the error path in bnxt_en (bsc#1220794).
- CVE-2021-47024: Fixed possible memory leak in vsock/virtio when closing socket (bsc#1220637).
- CVE-2021-47034: Fixed resolved pte update for kernel memory on radix in powerpc/64s (bsc#1220687).
- CVE-2021-47045: Fixed null pointer dereference in lpfc_prep_els_iocb() (bsc#1220640).
- CVE-2021-47049: Fixed Use after free in __vmbus_open() (bsc#1220692).
- CVE-2021-47055: Fixed missing permissions for locking and badblock ioctls in mtd (bsc#1220768).
- CVE-2021-47056: Fixed uninitialized lock in adf_vf2pf_shutdown() (bsc#1220769).
- CVE-2021-47060: Fixed a bug in KVM by stop looking for coalesced MMIO zones if the bus is destroyed (bsc#1220742).
- CVE-2021-47061: Fixed a bug in KVM by destroy I/O bus devices on unregister failure _after_ sync'ing SRCU (bsc#1220745).
- CVE-2021-47063: Fixed possible use-after-free in panel_bridge_detach() (bsc#1220777).
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.216.1", rls:"SLES12.0SP5"))) {
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
