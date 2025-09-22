# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100418");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CoreHTTP CGI Support RCE Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("corehttp/banner");
  script_require_ports("Services/www", 5555);

  script_tag(name:"summary", value:"CoreHTTP is prone to a remote command-execution vulnerability because
  the software fails to adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"Successful attacks can compromise the affected software and possibly
  the computer.");

  script_tag(name:"affected", value:"CoreHTTP 0.5.3.1 is vulnerable. Other versions may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37454");
  script_xref(name:"URL", value:"http://aconole.brad-x.com/advisories/corehttp.txt");

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

port = http_get_port(default:5555);
banner = http_get_remote_headers(port: port);
if(!banner)exit(0);

if(egrep(pattern:"Server: corehttp", string:banner)) {
  version = eregmatch(pattern: "Server: corehttp-([0-9.]+)", string: banner);
  if(!isnull(version[1])) {
    if(version_is_equal(version: version[1], test_version: "0.5.3.1")) {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(0);
