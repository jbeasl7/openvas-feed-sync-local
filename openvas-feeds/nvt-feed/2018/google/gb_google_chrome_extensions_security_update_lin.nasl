# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814068");
  script_version("2024-02-26T05:06:11+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-03 17:36:31 +0530 (Wed, 03 Oct 2018)");
  script_name("Google Chrome < 70.0.3538.35 Extensions Security Updates - Linux");

  script_tag(name:"summary", value:"Google Chrome extensions is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - If an extension asks for permission to read, write, and change data on all
    websites, there is no option available using which users can explicitly
    blacklist or white list a specific set of websites.

  - Code Obfuscation for Chrome Extensions.

  - Missing 2-Step Verification on Chrome Web Store accounts.

  - Absence of more in-depth review of extensions that ask for 'powerful permissions'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to automatically read and change data on websites using extensions, inject
  malicious code, conduct phishing attack and bypass security restrictions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 70.0.3538.35
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 70.0.3538.35
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://thehackernews.com/2018/10/google-chrome-extensions-security.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less(version:version, test_version:"70.0.3538.35")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"70.0.3538.35", install_path:location);
  security_message(data:report);
  exit(0);
}

exit(99);
