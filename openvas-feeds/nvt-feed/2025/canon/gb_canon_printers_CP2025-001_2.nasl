# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.171547");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-06-05 20:31:54 +0000 (Thu, 05 Jun 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-03 15:49:50 +0000 (Tue, 03 Jun 2025)");

  script_cve_id("CVE-2025-2146");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Canon Printers < 05.10 Buffer Overflow Vulnerability (CP2025-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_canon_printer_consolidation.nasl");
  script_mandatory_keys("canon/printer/detected");

  script_tag(name:"summary", value:"A buffer overflow vulnerability has been identified in the
  WebService Authentication processing for certain Canon Small Office Multifunction Printers and
  Laser Printers.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"These vulnerabilities indicate the possibility that, if a
  product is connected directly to the Internet without using a router (wired or Wi-Fi), an
  unauthenticated remote attacker may be able to execute arbitrary code and/or may be able to
  target the product in a Denial-of-Service (DoS) attack via the Internet.");

  script_tag(name:"affected", value:"Multiple Canon printers having firmware versions prior to
  05.10.");

  script_tag(name:"solution", value:"Update to version 05.10 or later.");

  script_xref(name:"URL", value:"https://psirt.canon/advisory-information/cp2025-001/");
  script_xref(name:"URL", value:"https://www.canon-europe.com/support/product-security/#news");
  script_xref(name:"URL", value:"https://canon.jp/support/support-info/250127vulnerability-response");
  script_xref(name:"URL", value:"https://canon.jp/-/media/Project/Canon/CanonJP/Website/support/support-info/250127vulnerability-response/model-250127.pdf?la=ja-JP&hash=6758FDBE18A851262D6547A0D8042CD3");
  script_xref(name:"URL", value:"https://canon.a.bigcontent.io/v1/static/cpe2025-001_affected_models_20250519_734151cbad864f8888e873ed88438ca5");
  script_xref(name:"URL", value:"https://www.usa.canon.com/support/canon-product-advisories/service-notice-regarding-vulnerability-measure-against-buffer-overflow-for-laser-printers-and-small-office-multifunctional-printers");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Added LBP and MF with and without i-SENSYS as i-SENSYS seems to be only a branding name
# Only some i-SENSYS X models were found online
cpe_list = make_list("cpe:/o:canon:mf457dw_firmware",
                     "cpe:/o:canon:mf551dw_firmware",
                     "cpe:/o:canon:mf656cdw_firmware",
                     "cpe:/o:canon:mf654cdw_firmware",
                     "cpe:/o:canon:mf653cdw_firmware",
                     "cpe:/o:canon:mf652cw_firmware",
                     "cpe:/o:canon:lbp632cdw_firmware",
                     "cpe:/o:canon:lbp633cdw_firmware",
                     "cpe:/o:canon:imagerunner_1643i_ii_firmware",
                     "cpe:/o:canon:imagerunner_1643if_ii_firmware",
                     "cpe:/o:canon:imagerunner_1643if_ii_firmware",
                     "cpe:/o:canon:i-sensys_lbp233dw_firmware",
                     "cpe:/o:canon:lbp233dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp236dw_firmware",
                     "cpe:/o:canon:lbp236dw_firmware",
                     "cpe:/o:canon:i-sensys_lbp631cw_firmware",
                     "cpe:/o:canon:lbp631cw_firmware",
                     "cpe:/o:canon:i-sensys_lbp633cdw_firmware",
                     "cpe:/o:canon:lbp633cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf453dw_firmware",
                     "cpe:/o:canon:mf453dw_firmware",
                     "cpe:/o:canon:i-sensys_mf455dw_firmware",
                     "cpe:/o:canon:mf455dw_firmware",
                     "cpe:/o:canon:i-sensys_mf552dw_firmware",
                     "cpe:/o:canon:mf552dw_firmware",
                     "cpe:/o:canon:i-sensys_mf553dw_firmware",
                     "cpe:/o:canon:mf553dw_firmware",
                     "cpe:/o:canon:i-sensys_mf651cw_firmware",
                     "cpe:/o:canon:mf651cw_firmware",
                     "cpe:/o:canon:i-sensys_mf655cdw_firmware",
                     "cpe:/o:canon:mf655cdw_firmware",
                     "cpe:/o:canon:i-sensys_mf657cdw_firmware",
                     "cpe:/o:canon:mf657cdw_firmware",
                     "cpe:/o:canon:i-sensys_x_1238i_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238if_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238p_ii_firmware",
                     "cpe:/o:canon:i-sensys_x_1238pr_ii_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list, first_cpe_only: TRUE))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "05.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "05.10");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
