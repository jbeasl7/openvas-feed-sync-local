# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sun:java_system_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900301");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-02-06 06:53:35 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0278");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sun Java System Application Server Information Disclosure vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33397");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/48161");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119166-35-1");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_java_app_serv_detect.nasl");
  script_mandatory_keys("sun_java_appserver/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation could allow remote unprivileged user to read Web
  Application configuration files in 'WEB-INF' and 'META-INF' directories.");

  script_tag(name:"affected", value:"Java System Application Server version 8.1 and 8.2 on Linux and Windows.");

  script_tag(name:"insight", value:"A security vulnerability in Java Application server may expose sensitive
  directory contents i.e. 'WEB-INF' and 'META-INF' via malformed requests.");

  script_tag(name:"summary", value:"Java Application Server is prone to an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the security updates.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^8\.[12]") {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
