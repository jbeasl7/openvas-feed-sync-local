# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800306");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5160");
  script_name("MyServer Remote Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/5184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27981");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("MyServer/banner");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful attacks will lead to denial of service to legitimate users.");

  script_tag(name:"affected", value:"MyServer MyServer version 0.8.11 and prior on all running platforms.");

  script_tag(name:"insight", value:"The flaw is due to multiple invalid requests in HTTP GET, DELETE,
  OPTIONS, and possibly other methods. These requests are related to '204 No Content error'.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to MyServer version 0.9 or later.");

  script_tag(name:"summary", value:"MyServer is prone to a denial of service (DoS) vulnerability.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);
banner = http_get_remote_headers(port:port);
if(!banner) exit(0);

mysvrVer = eregmatch(pattern:"MyServer ([0-9.]+)", string:banner);
if(mysvrVer[1] != NULL)
{
  # MyServer Version 0.8.11 and prior
  if(version_is_less_equal(version:mysvrVer[1], test_version:"0.8.11")){
    report = report_fixed_ver(installed_version:mysvrVer[1], vulnerable_range:"Less than or equal to 0.8.11");
    security_message(port: 0, data: report);
  }
}
