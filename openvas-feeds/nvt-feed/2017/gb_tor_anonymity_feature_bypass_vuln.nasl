# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tor:tor_browser";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811988");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-16541");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:30:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-11-09 16:08:09 +0530 (Thu, 09 Nov 2017)");
  script_name("Tor Browser Anonymity Feature Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_tor_browser_detect_lin.nasl");
  script_mandatory_keys("TorBrowser/Linux/Ver");

  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/tormoil-vulnerability-leaks-real-ip-address-from-tor-browser-users");

  script_tag(name:"summary", value:"Tor Browser is prone to anonymity feature bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in handling
  'file://' links which will cause Tor Browser to not to go through the network
  of Tor relays.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to obtain sensitive information that may aid in launching
  further attacks.");

  script_tag(name:"affected", value:"Tor Browser before 7.0.9");

  script_tag(name:"solution", value:"Upgrade to version 7.0.9 or later.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
torbVer = infos["version"];
torPath = infos["location"];

if(version_is_less(version:torbVer, test_version:"7.0.9")){
  report = report_fixed_ver(installed_version:torbVer, fixed_version:"7.0.9", install_path:torPath);
  security_message(port:0, data:report);
}

exit(0);
