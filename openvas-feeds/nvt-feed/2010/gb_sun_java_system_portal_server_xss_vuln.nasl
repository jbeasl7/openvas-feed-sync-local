# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801248");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2009-4187");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Sun Java System Portal Server Multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Dec/1023260.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37186");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-269368-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-138686-04-1");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sun_java_system_portal_server_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("sun/java/portal/server/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Sun Java System Portal Server Versions 6.3.1, 7.1, and 7.2.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input via the
  unspecified parameters to the Gateway component.");

  script_tag(name:"summary", value:"Sun Java System Portal Server is prone to multiple unspecified Cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Apply the referenced security patches.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:8080);

ver = get_kb_item("www/" + port + "/Sun/Java/Portal/Server");
if(ver != NULL)
{
  if(version_is_equal(version:ver, test_version:"6.3.1") ||
     version_is_equal(version:ver, test_version:"7.1")   ||
     version_is_equal(version:ver, test_version:"7.2")   ){
     security_message(port);
  }
}
