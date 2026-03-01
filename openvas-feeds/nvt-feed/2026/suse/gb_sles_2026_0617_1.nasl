# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0617.1");
  script_cve_id("CVE-2022-0854", "CVE-2022-48853", "CVE-2022-49604", "CVE-2022-49943", "CVE-2022-49980", "CVE-2022-50232", "CVE-2022-50614", "CVE-2022-50615", "CVE-2022-50617", "CVE-2022-50618", "CVE-2022-50619", "CVE-2022-50622", "CVE-2022-50623", "CVE-2022-50625", "CVE-2022-50626", "CVE-2022-50629", "CVE-2022-50630", "CVE-2022-50633", "CVE-2022-50635", "CVE-2022-50636", "CVE-2022-50638", "CVE-2022-50640", "CVE-2022-50641", "CVE-2022-50643", "CVE-2022-50644", "CVE-2022-50646", "CVE-2022-50649", "CVE-2022-50652", "CVE-2022-50653", "CVE-2022-50656", "CVE-2022-50658", "CVE-2022-50660", "CVE-2022-50661", "CVE-2022-50662", "CVE-2022-50664", "CVE-2022-50666", "CVE-2022-50668", "CVE-2022-50669", "CVE-2022-50670", "CVE-2022-50671", "CVE-2022-50672", "CVE-2022-50673", "CVE-2022-50675", "CVE-2022-50677", "CVE-2022-50678", "CVE-2022-50679", "CVE-2022-50697", "CVE-2022-50698", "CVE-2022-50699", "CVE-2022-50700", "CVE-2022-50702", "CVE-2022-50703", "CVE-2022-50704", "CVE-2022-50709", "CVE-2022-50715", "CVE-2022-50716", "CVE-2022-50717", "CVE-2022-50718", "CVE-2022-50719", "CVE-2022-50722", "CVE-2022-50724", "CVE-2022-50726", "CVE-2022-50727", "CVE-2022-50728", "CVE-2022-50730", "CVE-2022-50731", "CVE-2022-50732", "CVE-2022-50733", "CVE-2022-50735", "CVE-2022-50736", "CVE-2022-50740", "CVE-2022-50742", "CVE-2022-50744", "CVE-2022-50745", "CVE-2022-50747", "CVE-2022-50749", "CVE-2022-50750", "CVE-2022-50751", "CVE-2022-50752", "CVE-2022-50754", "CVE-2022-50755", "CVE-2022-50756", "CVE-2022-50757", "CVE-2022-50758", "CVE-2022-50760", "CVE-2022-50761", "CVE-2022-50763", "CVE-2022-50767", "CVE-2022-50769", "CVE-2022-50770", "CVE-2022-50773", "CVE-2022-50774", "CVE-2022-50776", "CVE-2022-50777", "CVE-2022-50779", "CVE-2022-50781", "CVE-2022-50782", "CVE-2022-50809", "CVE-2022-50814", "CVE-2022-50819", "CVE-2022-50821", "CVE-2022-50822", "CVE-2022-50823", "CVE-2022-50824", "CVE-2022-50826", "CVE-2022-50827", "CVE-2022-50828", "CVE-2022-50829", "CVE-2022-50830", "CVE-2022-50832", "CVE-2022-50834", "CVE-2022-50835", "CVE-2022-50836", "CVE-2022-50839", "CVE-2022-50840", "CVE-2022-50842", "CVE-2022-50843", "CVE-2022-50844", "CVE-2022-50845", "CVE-2022-50846", "CVE-2022-50848", "CVE-2022-50849", "CVE-2022-50850", "CVE-2022-50851", "CVE-2022-50853", "CVE-2022-50856", "CVE-2022-50858", "CVE-2022-50859", "CVE-2022-50860", "CVE-2022-50861", "CVE-2022-50864", "CVE-2022-50866", "CVE-2022-50868", "CVE-2022-50870", "CVE-2022-50872", "CVE-2022-50876", "CVE-2022-50878", "CVE-2022-50880", "CVE-2022-50881", "CVE-2022-50882", "CVE-2022-50884", "CVE-2022-50885", "CVE-2022-50886", "CVE-2022-50887", "CVE-2022-50888", "CVE-2022-50889", "CVE-2023-23559", "CVE-2023-52433", "CVE-2023-52923", "CVE-2023-53178", "CVE-2023-53215", "CVE-2023-53254", "CVE-2023-53407", "CVE-2023-53412", "CVE-2023-53417", "CVE-2023-53418", "CVE-2023-53743", "CVE-2023-53744", "CVE-2023-53746", "CVE-2023-53747", "CVE-2023-53751", "CVE-2023-53754", "CVE-2023-53755", "CVE-2023-53761", "CVE-2023-53766", "CVE-2023-53781", "CVE-2023-53783", "CVE-2023-53786", "CVE-2023-53788", "CVE-2023-53792", "CVE-2023-53794", "CVE-2023-53802", "CVE-2023-53803", "CVE-2023-53804", "CVE-2023-53808", "CVE-2023-53811", "CVE-2023-53814", "CVE-2023-53818", "CVE-2023-53819", "CVE-2023-53820", "CVE-2023-53827", "CVE-2023-53830", "CVE-2023-53832", "CVE-2023-53834", "CVE-2023-53837", "CVE-2023-53840", "CVE-2023-53842", "CVE-2023-53844", "CVE-2023-53845", "CVE-2023-53847", "CVE-2023-53850", "CVE-2023-53852", "CVE-2023-53858", "CVE-2023-53862", "CVE-2023-53866", "CVE-2023-53990", "CVE-2023-53991", "CVE-2023-53996", "CVE-2023-53998", "CVE-2023-54001", "CVE-2023-54003", "CVE-2023-54007", "CVE-2023-54009", "CVE-2023-54010", "CVE-2023-54014", "CVE-2023-54015", "CVE-2023-54018", "CVE-2023-54019", "CVE-2023-54020", "CVE-2023-54021", "CVE-2023-54024", "CVE-2023-54025", "CVE-2023-54026", "CVE-2023-54028", "CVE-2023-54036", "CVE-2023-54039", "CVE-2023-54040", "CVE-2023-54042", "CVE-2023-54045", "CVE-2023-54046", "CVE-2023-54048", "CVE-2023-54049", "CVE-2023-54050", "CVE-2023-54051", "CVE-2023-54053", "CVE-2023-54055", "CVE-2023-54058", "CVE-2023-54064", "CVE-2023-54072", "CVE-2023-54076", "CVE-2023-54078", "CVE-2023-54079", "CVE-2023-54083", "CVE-2023-54084", "CVE-2023-54090", "CVE-2023-54091", "CVE-2023-54092", "CVE-2023-54095", "CVE-2023-54096", "CVE-2023-54097", "CVE-2023-54098", "CVE-2023-54100", "CVE-2023-54102", "CVE-2023-54104", "CVE-2023-54108", "CVE-2023-54110", "CVE-2023-54111", "CVE-2023-54115", "CVE-2023-54118", "CVE-2023-54119", "CVE-2023-54120", "CVE-2023-54122", "CVE-2023-54123", "CVE-2023-54126", "CVE-2023-54127", "CVE-2023-54130", "CVE-2023-54131", "CVE-2023-54136", "CVE-2023-54140", "CVE-2023-54142", "CVE-2023-54146", "CVE-2023-54150", "CVE-2023-54153", "CVE-2023-54156", "CVE-2023-54159", "CVE-2023-54166", "CVE-2023-54168", "CVE-2023-54170", "CVE-2023-54171", "CVE-2023-54173", "CVE-2023-54177", "CVE-2023-54179", "CVE-2023-54183", "CVE-2023-54186", "CVE-2023-54189", "CVE-2023-54190", "CVE-2023-54197", "CVE-2023-54198", "CVE-2023-54199", "CVE-2023-54201", "CVE-2023-54202", "CVE-2023-54205", "CVE-2023-54208", "CVE-2023-54211", "CVE-2023-54213", "CVE-2023-54214", "CVE-2023-54219", "CVE-2023-54230", "CVE-2023-54236", "CVE-2023-54242", "CVE-2023-54243", "CVE-2023-54244", "CVE-2023-54245", "CVE-2023-54252", "CVE-2023-54260", "CVE-2023-54264", "CVE-2023-54266", "CVE-2023-54269", "CVE-2023-54270", "CVE-2023-54271", "CVE-2023-54274", "CVE-2023-54275", "CVE-2023-54277", "CVE-2023-54280", "CVE-2023-54284", "CVE-2023-54286", "CVE-2023-54287", "CVE-2023-54289", "CVE-2023-54292", "CVE-2023-54293", "CVE-2023-54294", "CVE-2023-54295", "CVE-2023-54298", "CVE-2023-54299", "CVE-2023-54300", "CVE-2023-54301", "CVE-2023-54302", "CVE-2023-54304", "CVE-2023-54305", "CVE-2023-54309", "CVE-2023-54311", "CVE-2023-54315", "CVE-2023-54317", "CVE-2023-54319", "CVE-2023-54321", "CVE-2023-54325", "CVE-2023-54326", "CVE-2024-26581", "CVE-2024-26832", "CVE-2024-28956", "CVE-2024-36348", "CVE-2024-36349", "CVE-2024-36350", "CVE-2024-36357", "CVE-2024-44987", "CVE-2024-46854", "CVE-2024-50143", "CVE-2024-54031", "CVE-2025-21658", "CVE-2025-21738", "CVE-2025-21760", "CVE-2025-21764", "CVE-2025-21765", "CVE-2025-21766", "CVE-2025-38068", "CVE-2025-38129", "CVE-2025-38159", "CVE-2025-38375", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38684", "CVE-2025-39977", "CVE-2025-40019", "CVE-2025-40044", "CVE-2025-40139", "CVE-2025-40215", "CVE-2025-40220", "CVE-2025-40233", "CVE-2025-40256", "CVE-2025-40257", "CVE-2025-40258", "CVE-2025-40277", "CVE-2025-40280", "CVE-2025-40300", "CVE-2025-40331", "CVE-2025-68183", "CVE-2025-68284", "CVE-2025-68285", "CVE-2025-68312", "CVE-2025-68732", "CVE-2025-68813", "CVE-2025-71085", "CVE-2025-71089", "CVE-2025-71112", "CVE-2025-71116", "CVE-2025-71120", "CVE-2026-22999", "CVE-2026-23001", "CVE-2026-23074", "CVE-2026-23089");
  script_tag(name:"creation_date", value:"2026-02-26 04:37:14 +0000 (Thu, 26 Feb 2026)");
  script_version("2026-02-27T05:55:46+0000");
  script_tag(name:"last_modification", value:"2026-02-27 05:55:46 +0000 (Fri, 27 Feb 2026)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-26 18:42:40 +0000 (Thu, 26 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0617-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260617-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210817");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254632");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254644");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254706");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255171");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255546");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256250");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257790");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024378.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to fix various security issues

The following security issues were fixed:

- CVE-2022-50630: mm: hugetlb: fix UAF in hugetlb_handle_userfault (bsc#1254785).
- CVE-2022-50697: mrp: introduce active flags to prevent UAF when applicant uninit (bsc#1255594).
- CVE-2022-50700: wifi: ath10k: Delay the unmapping of the buffer (bsc#1255576).
- CVE-2023-53215: sched/fair: Don't balance task to its current running CPU (bsc#1250397).
- CVE-2023-53254: cacheinfo: Fix shared_cpu_map to handle shared caches at different levels (bsc#1249871).
- CVE-2023-53781: smc: Fix use-after-free in tcp_write_timer_handler() (bsc#1254751).
- CVE-2023-54142: gtp: Fix use-after-free in __gtp_encap_destroy() (bsc#1256095).
- CVE-2023-54243: netfilter: ebtables: fix table blob use-after-free (bsc#1255908).
- CVE-2024-28956: x86/its: Enumerate Indirect Target Selection (ITS) bug (bsc#1242006).
- CVE-2024-36348: x86/bugs: Add a Transient Scheduler Attacks mitigation (bsc#1238896).
- CVE-2024-36349: x86/bugs: Add a Transient Scheduler Attacks mitigation (bsc#1238896).
- CVE-2024-36350: x86/bugs: Add a Transient Scheduler Attacks mitigation (bsc#1238896).
- CVE-2024-36357: x86/bugs: Add a Transient Scheduler Attacks mitigation (bsc#1238896).
- CVE-2024-44987: ipv6: prevent UAF in ip6_send_skb() (bsc#1230185).
- CVE-2024-46854: net: dpaa: Pad packets to ETH_ZLEN (bsc#1231084).
- CVE-2025-21738: ata: libata-sff: Ensure that we cannot write outside the allocated buffer (bsc#1238917).
- CVE-2025-38068: crypto: lzo - Fix compression buffer overrun (bsc#1245210).
- CVE-2025-38129: page_pool: fix inconsistency for page_pool_ring_lock() (bsc#1245723).
- CVE-2025-38159: wifi: rtw88: fix the 'para' buffer size to avoid reading out of bounds (bsc#1245751).
- CVE-2025-38375: virtio-net: ensure the received length does not exceed allocated size (bsc#1247177).
- CVE-2025-39977: futex: Prevent use-after-free during requeue-PI (bsc#1252046).
- CVE-2025-40019: crypto: essiv - Check ssize for decryption and in-place encryption (bsc#1252678).
- CVE-2025-40139: net: ipv4: Consolidate ipv4_mtu and ip_dst_mtu_maybe_forward (bsc#1253409).
- CVE-2025-40215: kABI: xfrm: delete x->tunnel as we delete x (bsc#1254959).
- CVE-2025-40220: fuse: fix livelock in synchronous file put from fuseblk workers (bsc#1254520).
- CVE-2025-40233: ocfs2: clear extent cache after moving/defragmenting extents (bsc#1254813).
- CVE-2025-40257: mptcp: fix a race in mptcp_pm_del_add_timer() (bsc#1254842).
- CVE-2025-40258: mptcp: fix race condition in mptcp_schedule_work() (bsc#1254843).
- CVE-2025-40277: drm/vmwgfx: Validate command header size against (bsc#1254894).
- CVE-2025-40280: tipc: Fix use-after-free in tipc_mon_reinit_self() (bsc#1254847).
- CVE-2025-40300: Documentation/hw-vuln: Add VMSCAPE documentation (bsc#1247483).
- CVE-2025-40331: sctp: Prevent TOCTOU out-of-bounds write ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.194.1.150400.24.98.3", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.194.1", rls:"SLES15.0SP4"))) {
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
