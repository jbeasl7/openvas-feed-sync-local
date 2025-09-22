# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803732");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2013-1616", "CVE-2013-1617", "CVE-2013-4670", "CVE-2013-4671",
                "CVE-2013-4672");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-08-06 15:41:47 +0530 (Tue, 06 Aug 2013)");
  script_name("Symantec Web Gateway Multiple Vulnerabilities (Aug 2013)");
  script_tag(name:"summary", value:"Symantec Web Gateway is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to Symantec Web Gateway version 5.1.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified errors related to the SWG console interface, login prompt of the
  SWG console and sudo configuration.

  - Certain unspecified input is not properly sanitised before being returned to
  the user.

  - The application allows users to perform certain actions via HTTP requests
  without performing any validity checks to verify the request.");
  script_tag(name:"affected", value:"Symantec Web Gateway versions prior to 5.1.1");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain escalated privileges and
conduct cross-site scripting and cross-site request forgery attacks and
compromise a vulnerable system.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/54294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61104");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61106");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/27136");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jul/177");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_web_gateway_detect.nasl");
  script_mandatory_keys("symantec_web_gateway/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"5.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.1.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
