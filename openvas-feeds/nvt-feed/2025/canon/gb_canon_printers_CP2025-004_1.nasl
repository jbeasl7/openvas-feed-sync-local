# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.171548");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-06 06:20:28 +0000 (Fri, 06 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2025-3078");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers Passback Vulnerability (CP2025-004, CVE-2025-3078)");

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

# nb: imageRUNNER ADVANCE is registered as imageRUNNER by detection
cpe_list = make_list("cpe:/o:canon:imagepress_c10000vp_firmware",
                     "cpe:/o:canon:imagepress_c10010vp_firmware",
                     "cpe:/o:canon:imagepress_c170_firmware",
                     "cpe:/o:canon:imagepress_c165_firmware",
                     "cpe:/o:canon:imagepress_c270_firmware",
                     "cpe:/o:canon:imagepress_c265_firmware",
                     "cpe:/o:canon:imagepress_c60_firmware",
                     "cpe:/o:canon:imagepress_c600_firmware",
                     "cpe:/o:canon:imagepress_c650_firmware",
                     "cpe:/o:canon:imagepress_c650i_firmware",
                     "cpe:/o:canon:imagepress_c700_firmware",
                     "cpe:/o:canon:imagepress_c710_firmware",
                     "cpe:/o:canon:imagepress_c750_firmware",
                     "cpe:/o:canon:imagepress_c800_firmware",
                     "cpe:/o:canon:imagepress_c8000vp_firmware",
                     "cpe:/o:canon:imagepress_c810_firmware",
                     "cpe:/o:canon:imagepress_c850_firmware",
                     "cpe:/o:canon:imagepress_c910_firmware",
                     "cpe:/o:canon:imagepress_c9010vp_firmware",
                     "cpe:/o:canon:imagepress_v900_firmware",
                     "cpe:/o:canon:imagepress_v800_firmware",
                     "cpe:/o:canon:imagepress_v700_firmware",
                     "cpe:/o:canon:imagepress_v1000_firmware",
                     "cpe:/o:canon:imagerunner_1435_firmware",
                     "cpe:/o:canon:imagerunner_1435i_firmware",
                     "cpe:/o:canon:imagerunner_1435if_firmware",
                     "cpe:/o:canon:imagerunner_1435p_firmware",
                     "cpe:/o:canon:imagerunner_2224_firmware",
                     "cpe:/o:canon:imagerunner_2224if_firmware",
                     "cpe:/o:canon:imagerunner_2224n_firmware",
                     "cpe:/o:canon:imagerunner_2425_firmware",
                     "cpe:/o:canon:imagerunner_2425i_firmware",
                     "cpe:/o:canon:imagerunner_2625i_firmware",
                     "cpe:/o:canon:imagerunner_2630i_firmware",
                     "cpe:/o:canon:imagerunner_2635i_firmware",
                     "cpe:/o:canon:imagerunner_2645i_firmware",
                     "cpe:/o:canon:imagerunner_2725i_firmware",
                     "cpe:/o:canon:imagerunner_2730i_firmware",
                     "cpe:/o:canon:imagerunner_2745i_firmware",
                     "cpe:/o:canon:imagerunner_2925i_firmware",
                     "cpe:/o:canon:imagerunner_2930i_firmware",
                     "cpe:/o:canon:imagerunner_2945i_firmware",
                     "cpe:/o:canon:imagerunner_3320_firmware",
                     "cpe:/o:canon:imagerunner_400i_firmware",
                     "cpe:/o:canon:imagerunner_4025i_firmware",
                     "cpe:/o:canon:imagerunner_4035i_firmware",
                     "cpe:/o:canon:imagerunner_4045i_firmware",
                     "cpe:/o:canon:imagerunner_4051i_firmware",
                     "cpe:/o:canon:imagerunner_4225i_firmware",
                     "cpe:/o:canon:imagerunner_4235i_firmware",
                     "cpe:/o:canon:imagerunner_4245i_firmware",
                     "cpe:/o:canon:imagerunner_4251i_firmware",
                     "cpe:/o:canon:imagerunner_4525i_firmware",
                     "cpe:/o:canon:imagerunner_4525i_iii_firmware",
                     "cpe:/o:canon:imagerunner_4535i_firmware",
                     "cpe:/o:canon:imagerunner_4535i_iii_firmware",
                     "cpe:/o:canon:imagerunner_4545i_firmware",
                     "cpe:/o:canon:imagerunner_4545i_iii_firmware",
                     "cpe:/o:canon:imagerunner_4551i_firmware",
                     "cpe:/o:canon:imagerunner_4551i_iii_firmware",
                     "cpe:/o:canon:imagerunner_500i_firmware",
                     "cpe:/o:canon:imagerunner_5235i_firmware",
                     "cpe:/o:canon:imagerunner_5240i_firmware",
                     "cpe:/o:canon:imagerunner_525i_firmware",
                     "cpe:/o:canon:imagerunner_525i_iii_firmware",
                     "cpe:/o:canon:imagerunner_525iz_firmware",
                     "cpe:/o:canon:imagerunner_525iz_iii_firmware",
                     "cpe:/o:canon:imagerunner_5535_firmware",
                     "cpe:/o:canon:imagerunner_5535i_firmware",
                     "cpe:/o:canon:imagerunner_5540i_firmware",
                     "cpe:/o:canon:imagerunner_6055_firmware",
                     "cpe:/o:canon:imagerunner_6055i_firmware",
                     "cpe:/o:canon:imagerunner_6065_firmware",
                     "cpe:/o:canon:imagerunner_6065i_firmware",
                     "cpe:/o:canon:imagerunner_6075_firmware",
                     "cpe:/o:canon:imagerunner_6075i_firmware",
                     "cpe:/o:canon:imagerunner_615i_firmware",
                     "cpe:/o:canon:imagerunner_615i_iii_firmware",
                     "cpe:/o:canon:imagerunner_615iz_firmware",
                     "cpe:/o:canon:imagerunner_615iz_iii_firmware",
                     "cpe:/o:canon:imagerunner_6255_firmware",
                     "cpe:/o:canon:imagerunner_6255i_firmware",
                     "cpe:/o:canon:imagerunner_6265_firmware",
                     "cpe:/o:canon:imagerunner_6265i_firmware",
                     "cpe:/o:canon:imagerunner_6275_firmware",
                     "cpe:/o:canon:imagerunner_6275i_firmware",
                     "cpe:/o:canon:imagerunner_6555_firmware",
                     "cpe:/o:canon:imagerunner_6555i_firmware",
                     "cpe:/o:canon:imagerunner_6555i_iii_firmware",
                     "cpe:/o:canon:imagerunner_6565_firmware",
                     "cpe:/o:canon:imagerunner_6565i_firmware",
                     "cpe:/o:canon:imagerunner_6565i_iii_firmware",
                     "cpe:/o:canon:imagerunner_6575_firmware",
                     "cpe:/o:canon:imagerunner_6575i_firmware",
                     "cpe:/o:canon:imagerunner_6575i_iii_firmware",
                     "cpe:/o:canon:imagerunner_7055i_firmware",
                     "cpe:/o:canon:imagerunner_715i_firmware",
                     "cpe:/o:canon:imagerunner_715i_iii_firmware",
                     "cpe:/o:canon:imagerunner_715iz_firmware",
                     "cpe:/o:canon:imagerunner_715iz_iii_firmware",
                     "cpe:/o:canon:imagerunner_7260i_firmware",
                     "cpe:/o:canon:imagerunner_7270i_firmware",
                     "cpe:/o:canon:imagerunner_7280i_firmware",
                     "cpe:/o:canon:imagerunner_8085_firmware",
                     "cpe:/o:canon:imagerunner_8085_pro_firmware",
                     "cpe:/o:canon:imagerunner_8095_firmware",
                     "cpe:/o:canon:imagerunner_8095_pro_firmware",
                     "cpe:/o:canon:imagerunner_8105_firmware",
                     "cpe:/o:canon:imagerunner_8105_pro_firmware",
                     "cpe:/o:canon:imagerunner_8205_firmware",
                     "cpe:/o:canon:imagerunner_8205_pro_firmware",
                     "cpe:/o:canon:imagerunner_8285_firmware",
                     "cpe:/o:canon:imagerunner_8285_pro_firmware",
                     "cpe:/o:canon:imagerunner_8295_firmware",
                     "cpe:/o:canon:imagerunner_8295_pro_firmware",
                     "cpe:/o:canon:imagerunner_8505_firmware",
                     "cpe:/o:canon:imagerunner_8505_iii_firmware",
                     "cpe:/o:canon:imagerunner_8585_firmware",
                     "cpe:/o:canon:imagerunner_8585_iii_firmware",
                     "cpe:/o:canon:imagerunner_8595_firmware",
                     "cpe:/o:canon:imagerunner_8595_iii_firmware",
                     "cpe:/o:canon:imagerunner_c2020_firmware",
                     "cpe:/o:canon:imagerunner_c2020i_firmware",
                     "cpe:/o:canon:imagerunner_c2020f_firmware",
                     "cpe:/o:canon:imagerunner_c2020l_firmware",
                     "cpe:/o:canon:imagerunner_c2025i_firmware",
                     "cpe:/o:canon:imagerunner_c2030_firmware",
                     "cpe:/o:canon:imagerunner_c2030f_firmware",
                     "cpe:/o:canon:imagerunner_c2030i_firmware",
                     "cpe:/o:canon:imagerunner_c2030l_firmware",
                     "cpe:/o:canon:imagerunner_c2220_firmware",
                     "cpe:/o:canon:imagerunner_c2220f_firmware",
                     "cpe:/o:canon:imagerunner_c2220i_firmware",
                     "cpe:/o:canon:imagerunner_c2220l_firmware",
                     "cpe:/o:canon:imagerunner_c2225i_firmware",
                     "cpe:/o:canon:imagerunner_c2230i_firmware",
                     "cpe:/o:canon:imagerunner_c250i_firmware",
                     "cpe:/o:canon:imagerunner_c255i_firmware",
                     "cpe:/o:canon:imagerunner_c256i_firmware",
                     "cpe:/o:canon:imagerunner_c256i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c3320f_firmware",
                     "cpe:/o:canon:imagerunner_c3320i_firmware",
                     "cpe:/o:canon:imagerunner_c3325i_firmware",
                     "cpe:/o:canon:imagerunner_c3330_firmware",
                     "cpe:/o:canon:imagerunner_c3330f_firmware",
                     "cpe:/o:canon:imagerunner_c3330i_firmware",
                     "cpe:/o:canon:imagerunner_c350f_firmware",
                     "cpe:/o:canon:imagerunner_c350i_firmware",
                     "cpe:/o:canon:imagerunner_c350p_firmware",
                     "cpe:/o:canon:imagerunner_c351f_firmware",
                     "cpe:/o:canon:imagerunner_c3520i_firmware",
                     "cpe:/o:canon:imagerunner_c3520i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c3525i_firmware",
                     "cpe:/o:canon:imagerunner_c3525i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c3530i_firmware",
                     "cpe:/o:canon:imagerunner_c3530i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c355i_firmware",
                     "cpe:/o:canon:imagerunner_c355ifc_firmware",
                     "cpe:/o:canon:imagerunner_c355p_firmware",
                     "cpe:/o:canon:imagerunner_c356i_firmware",
                     "cpe:/o:canon:imagerunner_c356i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c356p_firmware",
                     "cpe:/o:canon:imagerunner_c356p_iii_firmware",
                     "cpe:/o:canon:imagerunner_c475i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c475iz_iii_firmware",
                     "cpe:/o:canon:imagerunner_c478iz_firmware",
                     "cpe:/o:canon:imagerunner_c5030_firmware",
                     "cpe:/o:canon:imagerunner_c5030f_firmware",
                     "cpe:/o:canon:imagerunner_c5030i_firmware",
                     "cpe:/o:canon:imagerunner_c5035_firmware",
                     "cpe:/o:canon:imagerunner_c5035f_firmware",
                     "cpe:/o:canon:imagerunner_c5035i_firmware",
                     "cpe:/o:canon:imagerunner_c5045_firmware",
                     "cpe:/o:canon:imagerunner_c5045f_firmware",
                     "cpe:/o:canon:imagerunner_c5045i_firmware",
                     "cpe:/o:canon:imagerunner_c5051_firmware",
                     "cpe:/o:canon:imagerunner_c5051f_firmware",
                     "cpe:/o:canon:imagerunner_c5051i_firmware",
                     "cpe:/o:canon:imagerunner_c5235_firmware",
                     "cpe:/o:canon:imagerunner_c5235f_firmware",
                     "cpe:/o:canon:imagerunner_c5235i_firmware",
                     "cpe:/o:canon:imagerunner_c5240_firmware",
                     "cpe:/o:canon:imagerunner_c5240f_firmware",
                     "cpe:/o:canon:imagerunner_c5240i_firmware",
                     "cpe:/o:canon:imagerunner_c5250_firmware",
                     "cpe:/o:canon:imagerunner_c5250f_firmware",
                     "cpe:/o:canon:imagerunner_c5250i_firmware",
                     "cpe:/o:canon:imagerunner_c5255_firmware",
                     "cpe:/o:canon:imagerunner_c5255f_firmware",
                     "cpe:/o:canon:imagerunner_c5255i_firmware",
                     "cpe:/o:canon:imagerunner_c5535i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c5540i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c5550i_firmware",
                     "cpe:/o:canon:imagerunner_c5550i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c5560i_firmware",
                     "cpe:/o:canon:imagerunner_c5560i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c7055_firmware",
                     "cpe:/o:canon:imagerunner_c7065_firmware",
                     "cpe:/o:canon:imagerunner_c7065i_firmware",
                     "cpe:/o:canon:imagerunner_c7565i_firmware",
                     "cpe:/o:canon:imagerunner_c7565i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c7570i_firmware",
                     "cpe:/o:canon:imagerunner_c7570i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c7580i_firmware",
                     "cpe:/o:canon:imagerunner_c7580i_iii_firmware",
                     "cpe:/o:canon:imagerunner_c9060_firmware",
                     "cpe:/o:canon:imagerunner_c9070_firmware",
                     "cpe:/o:canon:imagerunner_c9280_firmware",
                     "cpe:/o:canon:imagerunner_dx_357p_firmware",
                     "cpe:/o:canon:imagerunner_dx_4725i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4735i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4745i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4751i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4825i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4835i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4845i_firmware",
                     "cpe:/o:canon:imagerunner_dx_4851i_firmware",
                     "cpe:/o:canon:imagerunner_dx_527iz_firmware",
                     "cpe:/o:canon:imagerunner_dx_6000i_firmware",
                     "cpe:/o:canon:imagerunner_dx_617i_firmware",
                     "cpe:/o:canon:imagerunner_dx_617iz_firmware",
                     "cpe:/o:canon:imagerunner_dx_6755i_firmware",
                     "cpe:/o:canon:imagerunner_dx_6765i_firmware",
                     "cpe:/o:canon:imagerunner_dx_6780i_firmware",
                     "cpe:/o:canon:imagerunner_dx_6860_firmware",
                     "cpe:/o:canon:imagerunner_dx_6860i_firmware",
                     "cpe:/o:canon:imagerunner_dx_6870_firmware",
                     "cpe:/o:canon:imagerunner_dx_6870i_firmware",
                     "cpe:/o:canon:imagerunner_dx_6980i_firmware",
                     "cpe:/o:canon:imagerunner_dx_717i_firmware",
                     "cpe:/o:canon:imagerunner_dx_717iz_firmware",
                     "cpe:/o:canon:imagerunner_dx_8705_firmware",
                     "cpe:/o:canon:imagerunner_dx_8786_firmware",
                     "cpe:/o:canon:imagerunner_dx_8795_firmware",
                     "cpe:/o:canon:imagerunner_dx_8905_firmware",
                     "cpe:/o:canon:imagerunner_dx_8905p_firmware",
                     "cpe:/o:canon:imagerunner_dx_c257i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c357i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3720i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3725i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3730i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3822i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3826i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3830i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c3835i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c477i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c477iz_firmware",
                     "cpe:/o:canon:imagerunner_dx_c478i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5735i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5740i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5750i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5760i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5840i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5850i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5860i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c5870i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c7765i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c7770i_firmware",
                     "cpe:/o:canon:imagerunner_dx_c7780i_firmware",
                     "cpe:/o:canon:imagerunner_c1325if_firmware",
                     "cpe:/o:canon:imagerunner_c1325if_firmware",
                     "cpe:/o:canon:imagerunner_c1325ifc_firmware",
                     "cpe:/o:canon:imagerunner_c1533if_firmware",
                     "cpe:/o:canon:imagerunner_c3025_firmware",
                     "cpe:/o:canon:imagerunner_c3025i_firmware",
                     "cpe:/o:canon:imagerunner_c3125i_firmware",
                     "cpe:/o:canon:imagerunner_c3226i_firmware",
                     "cpe:/o:canon:imagerunner_c3326i_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

# nb: These models have a fix version
if (cpe =~ "^cpe:/o:canon:imagepress_c[12](65|70)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagepress_v(7|8|9|10)00_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_29(25|30|45)i_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_45(25|35|45|51)i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_525(i|iz)_(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_55(35|35i|40i)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_[67]15(i|iz)_(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_65[567]5i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_85[089]5i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c25[56]i_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c256i_iii_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c35(20|25|30)i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c355(i|ifc|p)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c356[ip](|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c475(i|iz)_iii_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c478iz_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c55(35|40)i_iii_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c55[56]0i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c75(65|70|80)i(|_iii)_firmware" ||
    cpe =~ "^cpe:/o:canon:imagerunner_dx_" ||
    cpe =~ "^cpe:/o:canon:imagerunner_c3326i_firmware") {

  if (cpe =~ "^cpe:/o:canon:imagepress_c1(65|70)_firmware") {
    if (version_is_less(version: version, test_version: "47.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "47.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagepress_c2(65|70)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagepress_v(7|8|9|10)00_firmware") {
    if (version_is_less(version: version, test_version: "17.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "17.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_29(25|30|45)i_firmware") {
    if (version_is_less(version: version, test_version: "7.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "7.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_45(25|35|45|51)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_525(i|iz)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_55(35|35i|40i)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_[67]15(i|iz)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_65[567]5i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_85[089]5i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c25[56]i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c35(20|25|30)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c355(i|ifc|p)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c356[ip]_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c55[56]0i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c75(65|70|80)i_firmware") {
    if (version_is_less(version: version, test_version: "77.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "77.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_45(25|35|45|51)i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_525(i|iz)_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_[67]15(i|iz)_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_65[567]5i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_85[089]5i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c256i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c35(20|25|30)i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c356[ip]_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c475(i|iz)_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c5535i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c55[456]0i_iii_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_c75(65|70|80)i_iii_firmware") {
    if (version_is_less(version: version, test_version: "47.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "47.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_c478iz_firmware") {
    if (version_is_less(version: version, test_version: "27.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "27.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_dx_357p_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_47(25|35|45|51)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_527iz_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_6000i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_[67]17(i|iz)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_67(55|65|80|51)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_87(05|86|95)_firmware") {
    if (version_is_less(version: version, test_version: "37.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "37.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_dx_48(25|35|45|51)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_68[67]0(|i)_firmware") {
    if (version_is_less(version: version, test_version: "27.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "27.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_dx_6980i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_8905(|p)_firmware") {
    if (version_is_less(version: version, test_version: "7.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "7.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_dx_c[23]57i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_c37(20|25|30)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_c477i(|z)_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_c57(35|40|50|60)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_77(65|70|80)_firmware") {
    if (version_is_less(version: version, test_version: "37.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "37.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_dx_c38(22|26|30|35)i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_c478i_firmware" ||
      cpe =~ "^cpe:/o:canon:imagerunner_dx_c58[4567]0i_firmware") {
    if (version_is_less(version: version, test_version: "27.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "27.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  if (cpe =~ "^cpe:/o:canon:imagerunner_c3326i_firmware") {
    if (version_is_less(version: version, test_version: "7.09")) {
      report = report_fixed_ver(installed_version: version, fixed_version: "7.09");
      security_message(port: 0, data: report);
      exit(0);
    }
  }

  exit(99);
}

# nb: For all the models without a fixed version
report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
security_message(port: 0, data: report);
exit(0);
