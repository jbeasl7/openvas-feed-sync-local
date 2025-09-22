# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emc:rsa_authentication_agent_iis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804150");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-3280");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-25 15:39:27 +0530 (Mon, 25 Nov 2013)");
  script_name("RSA Authentication Agent for IIS Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"RSA Authentication Agent for IIS is prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 7.1.2 or later.");
  script_tag(name:"insight", value:"The flaw is due to fail open design error.");
  script_tag(name:"affected", value:"RSA Authentication Agent version 7.1.x before 7.1.2 for IIS.");
  script_tag(name:"impact", value:"Successful exploitation will allow local attacker to bypass certain security
restrictions and gain unauthorized privileged access.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/446935.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63303");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123755");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Oct/att-117/ESA-2013-067.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_rsa_auth_agent_detect_win.nasl");
  script_mandatory_keys("RSA/AuthenticationAgentWebIIS6432/Installed");
  script_xref(name:"URL", value:"http://www.rsa.com/node.aspx?id=2575");
  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");

rsaAutVer = get_app_version(cpe:CPE);
if(rsaAutVer && rsaAutVer =~ "^7\.1")
{
  if(version_is_less(version:rsaAutVer, test_version:"7.1.2"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
