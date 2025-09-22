# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170786");
  script_version("2024-05-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-17 05:05:27 +0000 (Fri, 17 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-14 19:35:38 +0000 (Tue, 14 May 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-21824");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Brother Printers Improper Authentication Vulnerability (Mar 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_brother_printer_consolidation.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_tag(name:"summary", value:"Multiple Brother printers are prone to an improper authentication
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable firmware version is present on the target host.");

  script_tag(name:"insight", value:"Attackers can gain access to the server's setting screen by obtaining
  session IDs of logged-in users and impersonating them, or by stealing login credentials and tricking users
  into opening malicious URLs.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN82749078/");
  script_xref(name:"URL", value:"https://support.brother.com/g/b/faqend.aspx?c=us&lang=en&prod=group2&faqid=faq00100823_000");
  script_xref(name:"URL", value:"https://support.brother.com/g/s/id/security/CVE-2024-21824_22475_modellist.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:brother:dcp-7090dw_firmware",
                     "cpe:/o:brother:dcp-7190dw_firmware",
                     "cpe:/o:brother:dcp-7195dw_firmware",
                     "cpe:/o:brother:dcp-8110dn_firmware",
                     "cpe:/o:brother:dcp-8150dn_firmware",
                     "cpe:/o:brother:dcp-8155dn_firmware",
                     "cpe:/o:brother:dcp-8250dn_firmware",
                     "cpe:/o:brother:dcp-9030cdn_firmware",
                     "cpe:/o:brother:dcp-b7520dw_firmware",
                     "cpe:/o:brother:dcp-b7530dn_firmware",
                     "cpe:/o:brother:dcp-b7535dw_firmware",
                     "cpe:/o:brother:dcp-l2530dw_firmware",
                     "cpe:/o:brother:dcp-l2531dw_firmware",
                     "cpe:/o:brother:dcp-l2532dw_firmware",
                     "cpe:/o:brother:dcp-l2535dw_firmware",
                     "cpe:/o:brother:dcp-l2537dw_firmware",
                     "cpe:/o:brother:dcp-l2550dn_firmware",
                     "cpe:/o:brother:dcp-l2550dw_firmware",
                     "cpe:/o:brother:dcp-l2551dn_firmware",
                     "cpe:/o:brother:dcp-l2551dw_firmware",
                     "cpe:/o:brother:dcp-l2552dn_firmware",
                     "cpe:/o:brother:dcp-l3510cdw_firmware",
                     "cpe:/o:brother:dcp-l3517cdw_firmware",
                     "cpe:/o:brother:dcp-l3550cdw_firmware",
                     "cpe:/o:brother:dcp-l3551cdw_firmware",
                     "cpe:/o:brother:dcp-l5500dn_firmware",
                     "cpe:/o:brother:dcp-l5502dn_firmware",
                     "cpe:/o:brother:dcp-l5600dn_firmware",
                     "cpe:/o:brother:dcp-l5602dn_firmware",
                     "cpe:/o:brother:dcp-l5650dn_firmware",
                     "cpe:/o:brother:dcp-l5652dn_firmware",
                     "cpe:/o:brother:dcp-l6600dw_firmware",
                     "cpe:/o:brother:dcp-l8400cdn_firmware",
                     "cpe:/o:brother:dcp-l8410cdw_firmware",
                     "cpe:/o:brother:dcp-l8450cdw_firmware",
                     "cpe:/o:brother:fax-l2710dn_firmware",
                     "cpe:/o:brother:hl-2595dw_firmware",
                     "cpe:/o:brother:hl-3160cdw_firmware",
                     "cpe:/o:brother:hl-3190cdw_firmware",
                     "cpe:/o:brother:hl-5450dn_firmware",
                     "cpe:/o:brother:hl-5470dw_firmware",
                     "cpe:/o:brother:hl-5590dn_firmware",
                     "cpe:/o:brother:hl-5595dn_firmware",
                     "cpe:/o:brother:hl-5595dnh_firmware",
                     "cpe:/o:brother:hl-6180dw_firmware",
                     "cpe:/o:brother:hl-b2050dn_firmware",
                     "cpe:/o:brother:hl-b2080dw_firmware",
                     "cpe:/o:brother:hl-l2325dw_firmware",
                     "cpe:/o:brother:hl-l2350dw_firmware",
                     "cpe:/o:brother:hl-l2351dw_firmware",
                     "cpe:/o:brother:hl-l2352dw_firmware",
                     "cpe:/o:brother:hl-l2357dw_firmware",
                     "cpe:/o:brother:hl-b2370dn_firmware",
                     "cpe:/o:brother:hl-b2370dw_firmware",
                     "cpe:/o:brother:hl-b2370dwxl_firmware",
                     "cpe:/o:brother:hl-b2371dn_firmware",
                     "cpe:/o:brother:hl-b2375dw_firmware",
                     "cpe:/o:brother:hl-b2376dw_firmware",
                     "cpe:/o:brother:hl-b2385dw_firmware",
                     "cpe:/o:brother:hl-l2386dw_firmware",
                     "cpe:/o:brother:hl-l2390dw_firmware",
                     "cpe:/o:brother:hl-l2395dw_firmware",
                     "cpe:/o:brother:hl-l3210dw_firmware",
                     "cpe:/o:brother:hl-l3230cdn_firmware",
                     "cpe:/o:brother:hl-l3230cdw_firmware",
                     "cpe:/o:brother:hl-l3270cdw_firmware",
                     "cpe:/o:brother:hl-l3290cdw_firmware",
                     "cpe:/o:brother:hl-l5050dn_firmware",
                     "cpe:/o:brother:hl-l5100dn_firmware",
                     "cpe:/o:brother:hl-l5100dnt_firmware",
                     "cpe:/o:brother:hl-l5102dw_firmware",
                     "cpe:/o:brother:hl-l5200dw_firmware",
                     "cpe:/o:brother:hl-l5200dwt_firmware",
                     "cpe:/o:brother:hl-l5202dw_firmware",
                     "cpe:/o:brother:hl-l6200dw_firmware",
                     "cpe:/o:brother:hl-l6200dwt_firmware",
                     "cpe:/o:brother:hl-l6202dw_firmware",
                     "cpe:/o:brother:hl-l6250dn_firmware",
                     "cpe:/o:brother:hl-l6250dw_firmware",
                     "cpe:/o:brother:hl-l6300dw_firmware",
                     "cpe:/o:brother:hl-l6300dwt_firmware",
                     "cpe:/o:brother:hl-l6400dw_firmware",
                     "cpe:/o:brother:hl-l6300dwg_firmware",
                     "cpe:/o:brother:hl-l6300dwt_firmware",
                     "cpe:/o:brother:hl-l6402dw_firmware",
                     "cpe:/o:brother:hl-l6450dw_firmware",
                     "cpe:/o:brother:hl-l8250cdn_firmware",
                     "cpe:/o:brother:hl-l8260cdn_firmware",
                     "cpe:/o:brother:hl-l8260cdw_firmware",
                     "cpe:/o:brother:hl-l8350cdw_firmware",
                     "cpe:/o:brother:hl-l8350cdwt_firmware",
                     "cpe:/o:brother:hl-l8360cdw_firmware",
                     "cpe:/o:brother:hl-l8360cdwt_firmware",
                     "cpe:/o:brother:hl-l9200cdw_firmware",
                     "cpe:/o:brother:hl-l9200cdwt_firmware",
                     "cpe:/o:brother:hl-l9300cdwt_firmware",
                     "cpe:/o:brother:hl-l9310cdw_firmware",
                     "cpe:/o:brother:mfc-7895dw_firmware",
                     "cpe:/o:brother:mfc-8510dn_firmware",
                     "cpe:/o:brother:mfc-8515dn_firmware",
                     "cpe:/o:brother:mfc-8520dn_firmware",
                     "cpe:/o:brother:mfc-8530dn_firmware",
                     "cpe:/o:brother:mfc-8540dn_firmware",
                     "cpe:/o:brother:mfc-8710dw_firmware",
                     "cpe:/o:brother:mfc-8810dw_firmware",
                     "cpe:/o:brother:mfc-8910dw_firmware",
                     "cpe:/o:brother:mfc-8950dw_firmware",
                     "cpe:/o:brother:mfc-9150cdn_firmware",
                     "cpe:/o:brother:mfc-9350cdw_firmware",
                     "cpe:/o:brother:mfc-b7715dw_firmware",
                     "cpe:/o:brother:mfc-b7720dn_firmware",
                     "cpe:/o:brother:mfc-l2690dw_firmware",
                     "cpe:/o:brother:mfc-l2710dn_firmware",
                     "cpe:/o:brother:mfc-l2710dw_firmware",
                     "cpe:/o:brother:mfc-l2712dn_firmware",
                     "cpe:/o:brother:mfc-l2712dw_firmware",
                     "cpe:/o:brother:mfc-l2713dw_firmware",
                     "cpe:/o:brother:mfc-l2715dw_firmware",
                     "cpe:/o:brother:mfc-l2716dw_firmware",
                     "cpe:/o:brother:mfc-l2717dw_firmware",
                     "cpe:/o:brother:mfc-l2730dn_firmware",
                     "cpe:/o:brother:mfc-l2730dw_firmware",
                     "cpe:/o:brother:mfc-l2732dw_firmware",
                     "cpe:/o:brother:mfc-l2750dw_firmware",
                     "cpe:/o:brother:mfc-l2750dwxl_firmware",
                     "cpe:/o:brother:mfc-l2751dw_firmware",
                     "cpe:/o:brother:mfc-l2752dw_firmware",
                     "cpe:/o:brother:mfc-l2759dw_firmware",
                     "cpe:/o:brother:mfc-l2770dw_firmware",
                     "cpe:/o:brother:mfc-l2771dw_firmware",
                     "cpe:/o:brother:mfc-l3710cw_firmware",
                     "cpe:/o:brother:mfc-l3730cdn_firmware",
                     "cpe:/o:brother:mfc-l3735cdn_firmware",
                     "cpe:/o:brother:mfc-l3745cdw_firmware",
                     "cpe:/o:brother:mfc-l3750cdw_firmware",
                     "cpe:/o:brother:mfc-l3770cdw_firmware",
                     "cpe:/o:brother:mfc-l5700dn_firmware",
                     "cpe:/o:brother:mfc-l5700dw_firmware",
                     "cpe:/o:brother:mfc-l5702dw_firmware",
                     "cpe:/o:brother:mfc-l5750dw_firmware",
                     "cpe:/o:brother:mfc-l5755dw_firmware",
                     "cpe:/o:brother:mfc-l5800dw_firmware",
                     "cpe:/o:brother:mfc-l5802dw_firmware",
                     "cpe:/o:brother:mfc-l5850dw_firmware",
                     "cpe:/o:brother:mfc-l5900dw_firmware",
                     "cpe:/o:brother:mfc-l5902dw_firmware",
                     "cpe:/o:brother:mfc-l6700dw_firmware",
                     "cpe:/o:brother:mfc-l6702dw_firmware",
                     "cpe:/o:brother:mfc-l6750dw_firmware",
                     "cpe:/o:brother:mfc-l6800dw_firmware",
                     "cpe:/o:brother:mfc-l6900dw_firmware",
                     "cpe:/o:brother:mfc-l6900dwg_firmware",
                     "cpe:/o:brother:mfc-l6902dw_firmware",
                     "cpe:/o:brother:mfc-l6950dw_firmware",
                     "cpe:/o:brother:mfc-l6970dw_firmware",
                     "cpe:/o:brother:mfc-l8600cdw_firmware",
                     "cpe:/o:brother:mfc-l8610cdw_firmware",
                     "cpe:/o:brother:mfc-l8650cdw_firmware",
                     "cpe:/o:brother:mfc-l8690cdw_firmware",
                     "cpe:/o:brother:mfc-l8850cdw_firmware",
                     "cpe:/o:brother:mfc-l8900cdw_firmware",
                     "cpe:/o:brother:mfc-l9550cdw_firmware",
                     "cpe:/o:brother:mfc-l9570cdw_firmware",
                     "cpe:/o:brother:mfc-l9577cdw_firmware",
                     "cpe:/o:brother:dcp-j1100dw_firmware",
                     "cpe:/o:brother:dcp-j572dw_firmware",
                     "cpe:/o:brother:dcp-j572n_firmware",
                     "cpe:/o:brother:dcp-j577n_firmware",
                     "cpe:/o:brother:dcp-j587n_firmware",
                     "cpe:/o:brother:dcp-j772dw_firmware",
                     "cpe:/o:brother:dcp-j774dw_firmware",
                     "cpe:/o:brother:dcp-j972n_firmware",
                     "cpe:/o:brother:dcp-j973n-b_firmware",
                     "cpe:/o:brother:dcp-j973n-w_firmware",
                     "cpe:/o:brother:dcp-j978n-b_firmware",
                     "cpe:/o:brother:dcp-j978n-w_firmware",
                     "cpe:/o:brother:dcp-j987n-b_firmware",
                     "cpe:/o:brother:dcp-j987n-w_firmware",
                     "cpe:/o:brother:dcp-j988n_firmware",
                     "cpe:/o:brother:dcp-t510w_firmware",
                     "cpe:/o:brother:dcp-t710w_firmware",
                     "cpe:/o:brother:hl-j6000dw_firmware",
                     "cpe:/o:brother:hl-j6100dw_firmware",
                     "cpe:/o:brother:mfc-j1300dw_firmware",
                     "cpe:/o:brother:mfc-j1500n_firmware",
                     "cpe:/o:brother:mfc-j1605dn_firmware",
                     "cpe:/o:brother:mfc-j2330dw_firmware",
                     "cpe:/o:brother:mfc-j2730dw_firmware",
                     "cpe:/o:brother:mfc-j3530dw_firmware",
                     "cpe:/o:brother:mfc-j3930dw_firmware",
                     "cpe:/o:brother:mfc-j4320dw_firmware",
                     "cpe:/o:brother:mfc-j491dw_firmware",
                     "cpe:/o:brother:mfc-j497dw_firmware",
                     "cpe:/o:brother:mfc-j5330dw_firmware",
                     "cpe:/o:brother:mfc-j5335dw_firmware",
                     "cpe:/o:brother:mfc-j5630cdw_firmware",
                     "cpe:/o:brother:mfc-j5730dw_firmware",
                     "cpe:/o:brother:mfc-j5830dw_firmware",
                     "cpe:/o:brother:mfc-j5845dw_firmware",
                     "cpe:/o:brother:mfc-j5930dw_firmware",
                     "cpe:/o:brother:mfc-j5945dw_firmware",
                     "cpe:/o:brother:mfc-j6530dw_firmware",
                     "cpe:/o:brother:mfc-j6535dw_firmware",
                     "cpe:/o:brother:mfc-j6580cdw_firmware",
                     "cpe:/o:brother:mfc-j6583cdw_firmware",
                     "cpe:/o:brother:mfc-j6730dw_firmware",
                     "cpe:/o:brother:mfc-j690dw_firmware",
                     "cpe:/o:brother:mfc-j6930dw_firmware",
                     "cpe:/o:brother:mfc-j6935dw_firmware",
                     "cpe:/o:brother:mfc-j6945dw_firmware",
                     "cpe:/o:brother:mfc-j6947dw_firmware",
                     "cpe:/o:brother:mfc-j6980cdw_firmware",
                     "cpe:/o:brother:mfc-j6995cdw_firmware",
                     "cpe:/o:brother:mfc-j6997cdw_firmware",
                     "cpe:/o:brother:mfc-j6999cdw_firmware",
                     "cpe:/o:brother:mfc-j738dn_firmware",
                     "cpe:/o:brother:mfc-j738dwn_firmware",
                     "cpe:/o:brother:mfc-j815dwxl_firmware",
                     "cpe:/o:brother:mfc-j890dw_firmware",
                     "cpe:/o:brother:mfc-j893n_firmware",
                     "cpe:/o:brother:mfc-j895dw_firmware",
                     "cpe:/o:brother:mfc-j898n_firmware",
                     "cpe:/o:brother:mfc-j995dw_firmware",
                     "cpe:/o:brother:mfc-j995dwxl_firmware",
                     "cpe:/o:brother:mfc-j998dn_firmware",
                     "cpe:/o:brother:mfc-j998dwn_firmware",
                     "cpe:/o:brother:mfc-t810w_firmware",
                     "cpe:/o:brother:mfc-t910dw_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

version = infos["version"];
cpe = infos["cpe"];

if (cpe == "cpe:/o:brother:dcp-7190dw_firmware") {
  if (version_is_less(version: version, test_version: "J")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-7195dw_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-81(10|50|55)dn_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-8250dn_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-9030cdn_firmware") {
  if (version_is_less(version: version, test_version: "ZB")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-b75(20|35)dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l253[01257]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-l255[01](dn|dw)_firmware" ||
    cpe == "cpe:/o:brother:dcp-l2552dn_firmware") {
  if (version_is_less(version: version, test_version: "ZA")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZA");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-b7530dn_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l351[07]cdw_firmware" ||
    cpe == "cpe:/o:brother:dcp-l3551cdw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-l3550cdw_firmware") {
  if (version_is_less(version: version, test_version: "ZB")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-l(550|560|565)[02]dn_firmware" ||
    cpe == "cpe:/o:brother:dcp-l6600dw_firmware") {
  if (version_is_less(version: version, test_version: "ZC")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZC");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-l8400cdn_firmware" ||
    cpe == "cpe:/o:brother:dcp-l8450cdw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-l8410cdw_firmware" ||
    cpe == "cpe:/o:brother:fax-l2710dn_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-2595dw_firmware" ||
    cpe == "cpe:/o:brother:hl-b2050dn_firmware" ||
    cpe == "cpe:/o:brother:hl-b2080dw_firmware") {
  if (version_is_less(version: version, test_version: "1.72")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.72");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-3160cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.38")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.38");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-3190cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.34")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.34");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-5450dn_firmware" ||
    cpe == "cpe:/o:brother:hl-5470dw_firmware" ||
    cpe == "cpe:/o:brother:hl-6180dw_firmware") {
  if (version_is_less(version: version, test_version: "1.26")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.26");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-559[05]dn_firmware" ||
    cpe == "cpe:/o:brother:hl-5595dnh_firmware") {
  if (version_is_less(version: version, test_version: "1.59")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.59");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2325w_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l235[0127]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l2370(dn|dw|dwxl)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l237[12]dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l23[78][56]dw_firmware") {
  if (version_is_less(version: version, test_version: "1.72")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.72");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l239[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "ZA")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZA");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l3210cw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l3230cd[nw]_firmware") {
  if (version_is_less(version: version, test_version: "1.38")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.38");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2370cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.34")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.34");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l2390cdw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l5050dn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l5100(dn|dnt)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l5[12]02dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l[56]200(dw|dwt)_firmware" ||
    cpe == "cpe:/o:brother:hl-l6202dw_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l6250(dn|dw)_firmware") {
  if (version_is_less(version: version, test_version: "1.59")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.59");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l6300(dw|dwt)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l6400(dw|dwg|dwt)_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l64(02|50)dw_firmware") {
  if (version_is_less(version: version, test_version: "1.64")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.64");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l8250cdn_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l8350(cdw|cdwt)_firmware") {
  if (version_is_less(version: version, test_version: "1.23")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.23");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l8260cd[nw]_firmware" ||
    cpe =~ "^cpe:/o:brother:hl-l8360(cdw|cdwt)_firmware" ||
    cpe == "cpe:/o:brother:hl-l9310cdw_firmware") {
  if (version_is_less(version: version, test_version: "1.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.4");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-l9200(cdw|cdwt)_firmware") {
  if (version_is_less(version: version, test_version: "1.22")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.22");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:hl-l9300cdwt_firmware") {
  if (version_is_less(version: version, test_version: "1.14")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.14");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-7895dw_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-85[12]0dn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-8[789]10dw_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-85[34]0dn_firmware") {
  if (version_is_less(version: version, test_version: "ZC")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZC");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-8950dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-9150cdn_firmware" ||
    cpe == "cpe:/o:brother:mfc-9350cdw_firmware") {
  if (version_is_less(version: version, test_version: "ZB")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-b7715dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2690dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l271[02]d[nw]_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l271[3567]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l273[02]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l275[0129]dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l2750dwxl_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l277[01]dw_firmware") {
  if (version_is_less(version: version, test_version: "ZA")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZA");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-b7720dn_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l3710cw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l373[05]cdn_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l37(45|50|70)cdw_firmware") {
  if (version_is_less(version: version, test_version: "ZB")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZB");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l5700(dn|dw)_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l57(02|50|55)dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l(58|67|69)(00|02|50)dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l590[02]dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l6800dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-l6900dwg_firmware" ||
    cpe == "cpe:/o:brother:mfc-l6970dw_firmware") {
  if (version_is_less(version: version, test_version: "ZC")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "ZC");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l8600cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l(86|88|95)50cdw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-l86[19]0cdw_firmware" ||
    cpe == "cpe:/o:brother:dcp-j1100dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-l8900cdw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-l957[07]cdw_firmware") {
  if (version_is_less(version: version, test_version: "Q")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j572dw_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j57[27]n_firmware") {
  if (version_is_less(version: version, test_version: "V")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "V");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j587n_firmware"||
    cpe =~ "^cpe:/o:brother:dcp-j987n-(b|w)_firmware") {
  if (version_is_less(version: version, test_version: "E")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "E");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-j77[24]dw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j972n_firmware" ||
    cpe =~ "^cpe:/o:brother:dcp-j97[38]n-(b|w)_firmware") {
  if (version_is_less(version: version, test_version: "X")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "X");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:dcp-j988n_firmware") {
  if (version_is_less(version: version, test_version: "Q")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Q");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:dcp-t[57]10w_firmware" ||
    cpe == "cpe:/o:brother:mfc-j1300dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j1500n_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:hl-j6[01]00dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j1605dn_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j(23|35)30dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j2730dw_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j3930dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j49[17]dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j533[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5630cdw_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j5[789]30dw_firmware") {
  if (version_is_less(version: version, test_version: "Y")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Y");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5845dw_firmware") {
  if (version_is_less(version: version, test_version: "N")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "N");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j5945dw_firmware" ||
    cpe == "cpe:/o:brother:mfc-j6583cdw_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j6[57]30dw_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6535dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j693[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "Z")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "Z");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j6580cdw_firmware") {
  if (version_is_less(version: version, test_version: "R")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "R");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j690dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j69(80|95)cdw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j694[57]dw_firmware" ||
    cpe =~ "^cpe:/o:brother:mfc-j699[79]dw_firmware") {
  if (version_is_less(version: version, test_version: "K")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "K");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j(738|998)(dn|dwn)_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:brother:mfc-j815dwxl_firmware") {
  if (version_is_less(version: version, test_version: "J")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "J");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j89[05]dw_firmware") {
  if (version_is_less(version: version, test_version: "S")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "S");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j89[38]n_firmware") {
  if (version_is_less(version: version, test_version: "W")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "W");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j995(dw|dwxl)_firmware" ||
    cpe == "cpe:/o:brother:mfc-t810w_firmware" ||
    cpe == "cpe:/o:brother:mfc-j910dw_firmware") {
  if (version_is_less(version: version, test_version: "P")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "P");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe =~ "^cpe:/o:brother:mfc-j998(dn|dwn)_firmware") {
  if (version_is_less(version: version, test_version: "L")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "L");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
