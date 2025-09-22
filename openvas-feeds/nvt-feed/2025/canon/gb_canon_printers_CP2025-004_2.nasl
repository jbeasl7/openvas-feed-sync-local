# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.171663");
  script_version("2025-08-12T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-12 05:40:06 +0000 (Tue, 12 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-08-07 09:58:50 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-3079");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers Passback Vulnerability (CP2025-004, CVE-2025-3079)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("General");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_tag(name:"summary", value:"A passback vulnerability has been identified for certain Canon
  Production Printers, Office/Small Office Multifunction Printers and Laser Printers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"This vulnerability could allow malicious actors, if they are
  able to obtain administrative privileges on the product, to acquire authentication information
  such as SMTP/LDAP connections configured within the product.");

  script_tag(name:"solution", value:"See the referenced advisory for a solution.");

  script_xref(name:"URL", value:"https://psirt.canon/advisory-information/cp2025-004/");
  script_xref(name:"URL", value:"https://www.canon-europe.com/support/product-security/#news");
  script_xref(name:"URL", value:"https://canon.jp/support/support-info/250519vulnerability-response");
  script_xref(name:"URL", value:"https://corporate.jp.canon/caution/160106");
  script_xref(name:"URL", value:"https://www.usa.canon.com/about-us/to-our-customers/cp2025-004-vulnerability-mitigation-remediation-for-production-printers-office-small-office-multifunction-printers-laser-printers");
  script_xref(name:"URL", value:"https://canon.jp/-/media/Project/Canon/CanonJP/Website/support/support-info/250519vulnerability-response/model-250519.pdf?la=ja-JP&hash=BC4FF64D1AC2F85D714DFA849DF241E6");
  script_xref(name:"URL", value:"https://canon.a.bigcontent.io/v1/static/cpe2025-004_affected_models_20250515_d1b01e64fcf64c419129260a6b9394b0");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb:
# - during testing, no LBP or MF models having the i-SENSYS prefix were observed
# - since i-SENSYS is mostly an european targeted line, and devices with same identifier,
# but no i-SENSYS prefix exist, I added them to the list also, to be on the safe side
# - also the JPN list seems to contain the same devices, without i-SENSYS, except for i-SENSYS X models
cpe_list = make_list("cpe:/o:canon:imagerunner_1133_firmware",
                     "cpe:/o:canon:imagerunner_1133if_firmware",
                     "cpe:/o:canon:imagerunner_1643i_ii_firmware",
                     "cpe:/o:canon:imagerunner_c1225_firmware",
                     "cpe:/o:canon:imagerunner_c1225if_firmware",
                     "cpe:/o:canon:imagerunner_c1538if_firmware",
                     "cpe:/o:canon:i-sensys_lbp212dw_firmware",
                     "cpe:/o:canon:lbp212dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp214dw_firmware",
                     "cpe:/o:canon:lbp214dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp215x_firmware",
                     "cpe:/o:canon:lbp215x_firmware",
                     "cpe:/o:canon:i-sensys_lbp226dw_firmware",
                     "cpe:/o:canon:lbp226dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp228x_firmware",
                     "cpe:/o:canon:lbp228x_firmware",
                     "cpe:/o:canon:i-sensys_lbp233dw_firmware",
                     "cpe:/o:canon:lbp233dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp236dw_firmware",
                     "cpe:/o:canon:lbp236dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp243dw_firmware",
                     "cpe:/o:canon:lbp243dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp246dw_firmware",
                     "cpe:/o:canon:lbp246dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp251dw_firmware",
                     "cpe:/o:canon:lbp251dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp252dw_firmware",
                     "cpe:/o:canon:lbp252dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp253x_firmware",
                     "cpe:/o:canon:lbp253x_firmware",
                     "cpe:/o:canon:i-sensys_lbp611cn_firmware",
                     "cpe:/o:canon:lbp611cn_firmware",
                     "cpe:/o:canon:i-sensys_lbp613cdw_firmware",
                     "cpe:/o:canon:lbp613cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp621cw_firmware",
                     "cpe:/o:canon:lbp621cw_firmware",
                     "cpe:/o:canon:i-sensys_lbp623cdw_firmware",
                     "cpe:/o:canon:lbp623cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp631cw_firmware",
                     "cpe:/o:canon:lbp631cw_firmware",
                     "cpe:/o:canon:i-sensys_lbp633cdw_firmware",
                     "cpe:/o:canon:lbp633cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp653cdw_firmware",
                     "cpe:/o:canon:lbp653cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp654cx_firmware",
                     "cpe:/o:canon:lbp654cx_firmware",
                     "cpe:/o:canon:i-sensys_lbp663cdw_firmware",
                     "cpe:/o:canon:lbp663cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp664cx_firmware",
                     "cpe:/o:canon:lbp664cx_firmware",
                     "cpe:/o:canon:i-sensys_lbp722cdw_firmware",
                     "cpe:/o:canon:lbp722cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf264dw_ii_firmware",
                     "cpe:/o:canon:mf264dw_ii_firmware",
                     "cpe:/o:canon:i-sensys_mf267dw_ii_firmware",
                     "cpe:/o:canon:mf267dw_ii_firmware",
                     "cpe:/o:canon:i-sensys_mf272dw_firmware",
                     "cpe:/o:canon:mf272dw_firmware",
                     "cpe:/o:canon:i-sensys_mf275dw_firmware",
                     "cpe:/o:canon:mf275dw_firmware",
                     "cpe:/o:canon:i-sensys_mf287dw_firmware",
                     "cpe:/o:canon:mf287dw_firmware",
                     "cpe:/o:canon:i-sensys_mf411dw_firmware",
                     "cpe:/o:canon:mf411dw_firmware",
                     "cpe:/o:canon:i-sensys_mf416dw_firmware",
                     "cpe:/o:canon:mf416dw_firmware",
                     "cpe:/o:canon:i-sensys_mf418x_firmware",
                     "cpe:/o:canon:mf418x_firmware",
                     "cpe:/o:canon:i-sensys_mf419x_firmware",
                     "cpe:/o:canon:mf419x_firmware",
                     "cpe:/o:canon:i-sensys_mf421dw_firmware",
                     "cpe:/o:canon:mf421dw_firmware",
                     "cpe:/o:canon:i-sensys_mf426dw_firmware",
                     "cpe:/o:canon:mf426dw_firmware",
                     "cpe:/o:canon:i-sensys_mf428x_firmware",
                     "cpe:/o:canon:mf428x_firmware",
                     "cpe:/o:canon:i-sensys_mf429x_firmware",
                     "cpe:/o:canon:mf429x_firmware",
                     "cpe:/o:canon:i-sensys_mf443dw_firmware",
                     "cpe:/o:canon:mf443dw_firmware",
                     "cpe:/o:canon:i-sensys_mf445dw_firmware",
                     "cpe:/o:canon:mf445dw_firmware",
                     "cpe:/o:canon:i-sensys_mf446x_firmware",
                     "cpe:/o:canon:mf446x_firmware",
                     "cpe:/o:canon:i-sensys_mf449x_firmware",
                     "cpe:/o:canon:mf449x_firmware",
                     "cpe:/o:canon:i-sensys_mf453dw_firmware",
                     "cpe:/o:canon:mf453dw_firmware",
                     "cpe:/o:canon:i-sensys_mf455dw_firmware",
                     "cpe:/o:canon:mf455dw_firmware",
                     "cpe:/o:canon:i-sensys_mf463dw_firmware",
                     "cpe:/o:canon:mf463dw_firmware",
                     "cpe:/o:canon:i-sensys_mf465dw_firmware",
                     "cpe:/o:canon:mf465dw_firmware",
                     "cpe:/o:canon:i-sensys_mf512x_firmware",
                     "cpe:/o:canon:mf512x_firmware",
                     "cpe:/o:canon:i-sensys_mf515x_firmware",
                     "cpe:/o:canon:mf515x_firmware",
                     "cpe:/o:canon:i-sensys_mf522x_firmware",
                     "cpe:/o:canon:mf522x_firmware",
                     "cpe:/o:canon:i-sensys_mf525x_firmware",
                     "cpe:/o:canon:mf525x_firmware",
                     "cpe:/o:canon:i-sensys_mf552dw_firmware",
                     "cpe:/o:canon:mf552dw_firmware",
                     "cpe:/o:canon:i-sensys_mf553dw_firmware",
                     "cpe:/o:canon:mf553dw_firmware",
                     "cpe:/o:canon:i-sensys_mf5940dn_firmware",
                     "cpe:/o:canon:mf5940dn_firmware",
                     "cpe:/o:canon:i-sensys_mf5980dw_firmware",
                     "cpe:/o:canon:mf5980dw_firmware",
                     "cpe:/o:canon:i-sensys_mf6140dn_firmware",
                     "cpe:/o:canon:mf6140dn_firmware",
                     "cpe:/o:canon:i-sensys_mf6180dw_firmware",
                     "cpe:/o:canon:mf6180dw_firmware",
                     "cpe:/o:canon:i-sensys_mf623cn_firmware",
                     "cpe:/o:canon:mf623cn_firmware",
                     "cpe:/o:canon:i-sensys_mf628cw_firmware",
                     "cpe:/o:canon:mf628cw_firmware",
                     "cpe:/o:canon:i-sensys_mf631cn_firmware",
                     "cpe:/o:canon:mf631cn_firmware",
                     "cpe:/o:canon:i-sensys_mf633cdw_firmware",
                     "cpe:/o:canon:mf633cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf635cx_firmware",
                     "cpe:/o:canon:mf635cx_firmware",
                     "cpe:/o:canon:i-sensys_mf641cw_firmware",
                     "cpe:/o:canon:mf641cw_firmware",
                     "cpe:/o:canon:i-sensys_mf643cdw_firmware",
                     "cpe:/o:canon:mf643cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf645cx_firmware",
                     "cpe:/o:canon:mf645cx_firmware",
                     "cpe:/o:canon:i-sensys_mf651cw_firmware",
                     "cpe:/o:canon:mf651cw_firmware",
                     "cpe:/o:canon:i-sensys_mf655cdw_firmware",
                     "cpe:/o:canon:mf655cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf657cdw_firmware",
                     "cpe:/o:canon:mf657cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf724cdw_firmware",
                     "cpe:/o:canon:mf724cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf728cdw_firmware",
                     "cpe:/o:canon:mf728cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf729cx_firmware",
                     "cpe:/o:canon:mf729cx_firmware",
                     "cpe:/o:canon:i-sensys_mf732cdw_firmware",
                     "cpe:/o:canon:mf732cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf734cdw_firmware",
                     "cpe:/o:canon:mf734cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf735cx_firmware",
                     "cpe:/o:canon:mf735cx_firmware",
                     "cpe:/o:canon:i-sensys_mf752cdw_firmware",
                     "cpe:/o:canon:mf752cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf754cdw_firmware",
                     "cpe:/o:canon:mf754cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf832cdw_firmware",
                     "cpe:/o:canon:mf832cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf8340_firmware",
                     "cpe:/o:canon:mf8340_firmware",
                     "cpe:/o:canon:i-sensys_mf8360_firmware",
                     "cpe:/o:canon:mf8360_firmware",
                     "cpe:/o:canon:i-sensys_mf8380_firmware",
                     "cpe:/o:canon:mf8380_firmware",
                     "cpe:/o:canon:i-sensys_x_1238i_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238if_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238p_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238pr_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1440i_firmware",
                     "cpe:/o:canon:i-sensys_x_1440if_firmware",
                     "cpe:/o:canon:i-sensys_x_1440p_firmware",
                     "cpe:/o:canon:i-sensys_x_1440pr_firmware",
                     "cpe:/o:canon:i-sensys_x_1861p_firmware",
                     "cpe:/o:canon:i-sensys_x_1871p_firmware",
                     "cpe:/o:canon:i-sensys_x_c1127p_firmware",
                     "cpe:/o:canon:i-sensys_x_c1333i_firmware",
                     "cpe:/o:canon:i-sensys_x_c1333if_firmware",
                     "cpe:/o:canon:i-sensys_x_c1533p_firmware",
                     "cpe:/o:canon:i-sensys_x_c1538p_firmware",
                     "cpe:/o:canon:i-sensys_x_c1936p_firmware",
                     "cpe:/o:canon:i-sensys_x_c1946p_firmware",
                     "cpe:/o:canon:i-sensys_x_mf8230cn_firmware",
                     "cpe:/o:canon:i-sensys_x_mf8280cw_firmware",
                     "cpe:/o:canon:i-sensys_x_mf8540cdn_firmware",
                     "cpe:/o:canon:i-sensys_x_mf8550cdn_firmware",
                     "cpe:/o:canon:i-sensys_x_mf8580cdw_firmware",
                     "cpe:/o:canon:i-sensys_lbp732cdw_firmware",
                     "cpe:/o:canon:lbp732cdw_firmware",
                     "cpe:/o:canon:i-sensys_x_c1533p_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_c1538p_ii_firmware",
                     "cpe:/o:canon:i-sensys_mf842cdw_firmware",
                     "cpe:/o:canon:mf842cdw_firmware",
                     "cpe:/o:canon:i-sensys_x_c1533if_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_c1538if_ii_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

# nb: These models have a fix version
if (cpe =~ "^cpe:/o:canon:i-sensys_x_c153[38](p|if)_ii_firmware" ||
    cpe =~ "^cpe:/o:canon:(i-sensys_)?lbp732cdw_firmware" ||
    cpe =~ "^cpe:/o:canon:(i-sensys_)?mf842cdw_firmware") {
  if (version_is_less(version: version, test_version: "8.16")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "8.16");
    security_message(port: 0, data: report);
    exit(0);
  }
  exit(99);
}

# nb: For all the models without a fixed version
report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
security_message(port: 0, data: report);
exit(0);
