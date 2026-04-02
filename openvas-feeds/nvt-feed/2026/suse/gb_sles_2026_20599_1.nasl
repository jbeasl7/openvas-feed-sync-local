# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20599.1");
  script_cve_id("CVE-2024-54031", "CVE-2025-37744", "CVE-2025-37751", "CVE-2025-37841", "CVE-2025-37845", "CVE-2025-37904", "CVE-2025-37955", "CVE-2025-38243", "CVE-2025-38262", "CVE-2025-38297", "CVE-2025-38298", "CVE-2025-38379", "CVE-2025-38423", "CVE-2025-38505", "CVE-2025-38507", "CVE-2025-38510", "CVE-2025-38511", "CVE-2025-38512", "CVE-2025-38513", "CVE-2025-38515", "CVE-2025-38516", "CVE-2025-38520", "CVE-2025-38521", "CVE-2025-38529", "CVE-2025-38530", "CVE-2025-38535", "CVE-2025-38537", "CVE-2025-38538", "CVE-2025-38539", "CVE-2025-38540", "CVE-2025-38541", "CVE-2025-38543", "CVE-2025-38547", "CVE-2025-38548", "CVE-2025-38550", "CVE-2025-38551", "CVE-2025-38569", "CVE-2025-38589", "CVE-2025-38590", "CVE-2025-38645", "CVE-2025-39689", "CVE-2025-39795", "CVE-2025-39813", "CVE-2025-39814", "CVE-2025-39817", "CVE-2025-39829", "CVE-2025-39880", "CVE-2025-39913", "CVE-2025-39927", "CVE-2025-40030", "CVE-2025-40045", "CVE-2025-40097", "CVE-2025-40106", "CVE-2025-40147", "CVE-2025-40195", "CVE-2025-40257", "CVE-2025-40259", "CVE-2025-40261", "CVE-2025-40363", "CVE-2025-68174", "CVE-2025-68178", "CVE-2025-68188", "CVE-2025-68200", "CVE-2025-68211", "CVE-2025-68218", "CVE-2025-68227", "CVE-2025-68241", "CVE-2025-68245", "CVE-2025-68261", "CVE-2025-68296", "CVE-2025-68297", "CVE-2025-68320", "CVE-2025-68325", "CVE-2025-68337", "CVE-2025-68341", "CVE-2025-68348", "CVE-2025-68349", "CVE-2025-68356", "CVE-2025-68359", "CVE-2025-68360", "CVE-2025-68361", "CVE-2025-68366", "CVE-2025-68367", "CVE-2025-68368", "CVE-2025-68372", "CVE-2025-68374", "CVE-2025-68376", "CVE-2025-68379", "CVE-2025-68725", "CVE-2025-68735", "CVE-2025-68741", "CVE-2025-68743", "CVE-2025-68764", "CVE-2025-68768", "CVE-2025-68770", "CVE-2025-68771", "CVE-2025-68773", "CVE-2025-68775", "CVE-2025-68776", "CVE-2025-68777", "CVE-2025-68778", "CVE-2025-68783", "CVE-2025-68784", "CVE-2025-68788", "CVE-2025-68789", "CVE-2025-68792", "CVE-2025-68795", "CVE-2025-68797", "CVE-2025-68798", "CVE-2025-68799", "CVE-2025-68800", "CVE-2025-68801", "CVE-2025-68802", "CVE-2025-68803", "CVE-2025-68804", "CVE-2025-68808", "CVE-2025-68811", "CVE-2025-68813", "CVE-2025-68814", "CVE-2025-68815", "CVE-2025-68816", "CVE-2025-68819", "CVE-2025-68820", "CVE-2025-68821", "CVE-2025-68822", "CVE-2025-71064", "CVE-2025-71066", "CVE-2025-71073", "CVE-2025-71076", "CVE-2025-71077", "CVE-2025-71078", "CVE-2025-71079", "CVE-2025-71080", "CVE-2025-71081", "CVE-2025-71082", "CVE-2025-71083", "CVE-2025-71084", "CVE-2025-71085", "CVE-2025-71086", "CVE-2025-71087", "CVE-2025-71088", "CVE-2025-71089", "CVE-2025-71091", "CVE-2025-71093", "CVE-2025-71094", "CVE-2025-71095", "CVE-2025-71097", "CVE-2025-71098", "CVE-2025-71099", "CVE-2025-71100", "CVE-2025-71101", "CVE-2025-71108", "CVE-2025-71111", "CVE-2025-71112", "CVE-2025-71113", "CVE-2025-71114", "CVE-2025-71116", "CVE-2025-71118", "CVE-2025-71119", "CVE-2025-71120", "CVE-2025-71123", "CVE-2025-71126", "CVE-2025-71130", "CVE-2025-71131", "CVE-2025-71132", "CVE-2025-71133", "CVE-2025-71135", "CVE-2025-71136", "CVE-2025-71137", "CVE-2025-71138", "CVE-2025-71141", "CVE-2025-71142", "CVE-2025-71143", "CVE-2025-71145", "CVE-2025-71147", "CVE-2025-71148", "CVE-2025-71149", "CVE-2025-71154", "CVE-2025-71156", "CVE-2025-71157", "CVE-2025-71162", "CVE-2025-71163", "CVE-2026-22976", "CVE-2026-22977", "CVE-2026-22978", "CVE-2026-22981", "CVE-2026-22982", "CVE-2026-22984", "CVE-2026-22985", "CVE-2026-22986", "CVE-2026-22988", "CVE-2026-22989", "CVE-2026-22990", "CVE-2026-22991", "CVE-2026-22992", "CVE-2026-22993", "CVE-2026-22996", "CVE-2026-22997", "CVE-2026-22999", "CVE-2026-23000", "CVE-2026-23001", "CVE-2026-23002", "CVE-2026-23005", "CVE-2026-23006", "CVE-2026-23011");
  script_tag(name:"creation_date", value:"2026-03-09 04:38:35 +0000 (Mon, 09 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 19:23:11 +0000 (Wed, 25 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20599-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620599-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253079");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255319");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255529");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257603");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024614.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:20599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 16.0 and SL MIxro 6.2 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2025-40147: blk-throttle: fix access race during throttle policy activation (bsc#1253344).
- CVE-2025-40257: mptcp: fix a race in mptcp_pm_del_add_timer() (bsc#1254842).
- CVE-2025-40259: scsi: sg: Do not sleep in atomic context (bsc#1254845).
- CVE-2025-40261: nvme: nvme-fc: Ensure ->ioerr_work is cancelled in nvme_fc_delete_ctrl() (bsc#1254839).
- CVE-2025-40363: net: ipv6: fix field-spanning memcpy warning in AH output (bsc#1255102).
- CVE-2025-68174: amd/amdkfd: enhance kfd process check in switch partition (bsc#1255327).
- CVE-2025-68178: blk-cgroup: fix possible deadlock while configuring policy (bsc#1255266).
- CVE-2025-68188: tcp: use dst_dev_rcu() in tcp_fastopen_active_disable_ofo_check() (bsc#1255269).
- CVE-2025-68200: bpf: Add bpf_prog_run_data_pointers() (bsc#1255241).
- CVE-2025-68211: ksm: use range-walk function to jump over holes in scan_get_next_rmap_item (bsc#1255319).
- CVE-2025-68218: nvme-multipath: fix lockdep WARN due to partition scan work (bsc#1255245).
- CVE-2025-68227: mptcp: Fix proto fallback detection with BPF (bsc#1255216).
- CVE-2025-68241: ipv4: route: Prevent rt_bind_exception() from rebinding stale fnhe (bsc#1255157).
- CVE-2025-68245: net: netpoll: fix incorrect refcount handling causing incorrect cleanup (bsc#1255268).
- CVE-2025-68261: ext4: add i_data_sem protection in ext4_destroy_inline_data_nolock() (bsc#1255164).
- CVE-2025-68296: drm, fbcon, vga_switcheroo: Avoid race condition in fbcon setup (bsc#1255128).
- CVE-2025-68297: ceph: fix crash in process_v2_sparse_read() for encrypted directories (bsc#1255403).
- CVE-2025-68320: lan966x: Fix sleeping in atomic context (bsc#1255172).
- CVE-2025-68325: net/sched: sch_cake: Fix incorrect qlen reduction in cake_drop (bsc#1255417).
- CVE-2025-68337: jbd2: avoid bug_on in jbd2_journal_get_create_access() when file system corrupted (bsc#1255482).
- CVE-2025-68341: veth: reduce XDP no_direct return section to fix race (bsc#1255506).
- CVE-2025-68348: block: fix memory leak in __blkdev_issue_zero_pages (bsc#1255694).
- CVE-2025-68349: NFSv4/pNFS: Clear NFS_INO_LAYOUTCOMMIT in pnfs_mark_layout_stateid_invalid (bsc#1255544).
- CVE-2025-68356: gfs2: Prevent recursive memory reclaim (bsc#1255593).
- CVE-2025-68359: btrfs: fix double free of qgroup record after failure to add delayed ref head (bsc#1255542).
- CVE-2025-68360: wifi: mt76: wed: use proper wed reference in mt76 wed driver callabacks (bsc#1255536).
- CVE-2025-68361: erofs: limit the level of fs stacking for file-backed mounts (bsc#1255526).
- CVE-2025-68366: nbd: defer config unlock in nbd_genl_connect (bsc#1255622).
- CVE-2025-68367: macintosh/mac_hid: fix race condition in mac_hid_toggle_emumouse (bsc#1255547).
- CVE-2025-68368: md: init bioset in mddev_init (bsc#1255527).
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.12.0~160000.26.1.160000.2.7", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.12.0~160000.26.1", rls:"SLES16.0.0"))) {
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
