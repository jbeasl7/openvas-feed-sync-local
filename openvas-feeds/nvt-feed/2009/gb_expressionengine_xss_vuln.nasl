# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800263");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1070");
  script_name("ExpressionEngine CMS Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34193");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49359");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/502045/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_expressionengine_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("expression_engine/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in an image by tricking the user to view a malicious profile page.");

  script_tag(name:"affected", value:"ExpressionEngine versions prior to 1.6.7 on all platforms.");

  script_tag(name:"insight", value:"Inadequate validation of user supplied input to the system/index.php script
  leads to cross site attacks.");

  script_tag(name:"solution", value:"Update ExpressionEngine to version 1.6.7.");

  script_tag(name:"summary", value:"ExpressionEngine CMS is prone to a Cross Site Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

httpPort = http_get_port(default:80);

expressionVer = get_kb_item("www/" + httpPort + "/ExpEngine");
if(expressionVer == NULL)
  exit(0);

if(version_is_less(version:expressionVer, test_version:"1.6.7")){
  report = report_fixed_ver(installed_version:expressionVer, fixed_version:"1.6.7");
  security_message(port: httpPort, data: report);
  exit(0);
}

exit(99);
