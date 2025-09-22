# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813391");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-16 14:29:00 +0000 (Fri, 16 Nov 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11581");

  script_name("Brother HL Series Printer XSS Vulnerability");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_brother_printer_consolidation.nasl");
  script_mandatory_keys("brother/printer/detected");

  script_tag(name:"summary", value:"Brother HL Series Printer is prone to a cross site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to am improper validation of url parameter to
  'etc/loginerror.html'.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to inject arbitrary
  html and script code into the web site. This would alter the appearance and would make it possible
  to initiate further attacks against site visitors.");

  script_tag(name:"affected", value:"Brother HL-L2340D and HL-L2380DW series printers firmware version
  prior to 1.16.");

  script_tag(name:"solution", value:"Update to firmware version 1.16 or later and set a new password.
  Please see the references for more information.");

  script_xref(name:"URL", value:"https://gist.github.com/huykha/409451e4b086bfbd55e28e7e803ae930");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list("cpe:/o:brother:hl-l2340d_firmware",
                     "cpe:/o:brother:hl-l2380dw_firmware");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

CPE  = infos["cpe"];
port = infos["port"];

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"1.16")){
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.16", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
