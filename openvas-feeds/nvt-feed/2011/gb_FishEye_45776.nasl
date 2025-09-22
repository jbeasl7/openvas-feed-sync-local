# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103027");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-01-13 13:28:59 +0100 (Thu, 13 Jan 2011)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Atlassian Fisheye < 2.4.4Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45776");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/crucible/");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/fisheye/");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/FISHEYE/FishEye+and+Crucible+Security+Advisory+2011-01-12");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/CRUCIBLE/FishEye+and+Crucible+Security+Advisory+2011-01-12");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_FishEye_detect.nasl");
  script_require_ports("Services/www", 8060);
  script_mandatory_keys("FishEye/installed");

  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Fisheye and Crucible are prone to cross-site scripting, security-
  bypass, and information disclosure vulnerabilities.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to execute arbitrary script code in
  the context of the website, steal cookie-based authentication
  information, disclose sensitive information, or bypass certain security restrictions.");

  script_tag(name:"affected", value:"Fisheye and Crucible versions prior to 2.4.4 are vulnerable.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:8060);
vers = get_kb_item(string("www/", port, "/FishEye"));
if(vers) {
  if(version_is_less(version: vers, test_version: "2.4.4")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"2.4.4");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
