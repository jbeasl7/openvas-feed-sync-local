# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:barracudadrive:barracudadrive";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804611");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2014-3808");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-06-02 11:14:12 +0530 (Mon, 02 Jun 2014)");
  script_name("BarracudaDrive Multiple XSS Vulnerabilities -02 (Jun 2014)");

  script_tag(name:"summary", value:"BarracudaDrive is prone to multiple XSS vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Input passed via the 'role' parameter to 'protected/admin/roles.lsp',
'name' parameter to '/admin/user.lsp', path' parameter in
'/rtl/protected/admin/wizard/setuser.lsp', 'host' parameter in
'/admin/tunnelconstr.lsp', 'newpath' parameter in
'protected/admin/wfsconstr.lsp' is not properly verified before it is returned
to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of a
vulnerable site.");
  script_tag(name:"affected", value:"BarracudaDrive version 6.x before 6.7.2");
  script_tag(name:"solution", value:"Upgrade to BarracudaDrive version 6.7.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67138");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Advistory_BarracudaDrive_6.7.1_Mult_XSS_Vuln.txt");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_barracuda_drive_detect.nasl");
  script_mandatory_keys("BarracudaDrive/Installed");
  script_xref(name:"URL", value:"http://barracudadrive.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!bdPort = get_app_port(cpe:CPE)){
  exit(0);
}

bdVer = get_app_version(cpe:CPE, port:bdPort);
if(!bdVer){
  exit(0);
}

if(version_in_range(version:bdVer, test_version:"6.0", test_version2:"6.7.1"))
{
  report = report_fixed_ver(installed_version:bdVer, vulnerable_range:"6.0 - 6.7.1");
  security_message(port:bdPort, data:report);
  exit(0);
}
