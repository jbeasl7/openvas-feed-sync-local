# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:openadmin_tool";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802159");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");

  script_cve_id("CVE-2011-3390");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("IBM Open Admin Tool 'index.php' Multiple Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69488");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49364");
  script_xref(name:"URL", value:"http://voidroot.blogspot.com/2011/08/xss-in-ibm-open-admin-tool.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/104617/ibmopenadmin-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/519468/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_openadmin_tool_detect.nasl");
  script_mandatory_keys("ibm_openadmin/installed");

  script_tag(name:"insight", value:"The flaws are due to the improper validation of user supplied input via
'host', 'port', 'username', 'userpass' and 'informixserver' parameters in 'index.php'.");

  script_tag(name:"solution", value:"Upgrade to IBM OpenAdmin Tool (OAT) version 2.72 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"IBM Open Admin Tool is prone to multiple cross-site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site and steal the victim's cookie-based
authentication credentials.");

  script_tag(name:"affected", value:"IBM OpenAdmin Tool (OAT) version before 2.72");

  script_xref(name:"URL", value:"https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=swg-informixfpd&lang=en_US&S_PKG=dl&cp=UTF-8");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!ver = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version:ver, test_version:"2.72")){
  report = report_fixed_ver(installed_version: ver, fixed_version: "2.72");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
