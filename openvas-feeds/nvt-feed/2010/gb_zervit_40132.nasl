# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100637");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Zervit HTTP Server Source Code Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40132");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zervit/banner");

  script_tag(name:"summary", value:"Zervit is prone to a vulnerability that lets attackers access source
  code files.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to retrieve certain files
  from the vulnerable computer in the context of the webserver process.
  Information obtained may aid in further attacks.");

  script_tag(name:"affected", value:"Zervit 0.4 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: Zervit" >!< banner)
  exit(0);

version = eregmatch(pattern:"Server: Zervit ([0-9.]+)", string: banner);

if(isnull(version[1]))exit(0);
vers = version[1];

if(!isnull(vers)) {
  if(version_is_equal(version: vers, test_version: "0.4")) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
