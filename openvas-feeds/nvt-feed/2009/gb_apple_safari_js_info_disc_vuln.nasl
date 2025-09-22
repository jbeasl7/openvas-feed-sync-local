# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900075");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_cve_id("CVE-2008-5914");
  script_name("Apple Safari JavaScript Engine Cross Domain Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33276");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apple_safari_smb_login_detect.nasl");
  script_mandatory_keys("apple/safari/smb-login/detected");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in
  the context of the web browser and can spoof sensitive information of the remote user through the web browser.");

  script_tag(name:"affected", value:"Apple Safari 3.1.2 and prior on Windows.");

  script_tag(name:"insight", value:"Undefined function in the JavaScript implementation of the browser fails
  to properly enforce the origin policy and leaves temporary footprints.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.0 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to an information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"3.525.21.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
