# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103012");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");

  script_name("DD-WRT '/Info.live.htm' Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45598");
  script_xref(name:"URL", value:"http://www.dd-wrt.com/dd-wrtv3/dd-wrt/about.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Dec/651");

  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_app");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"DD-WRT is prone to multiple remote information-disclosure issues
  because it fails to restrict access to sensitive information.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to obtain sensitive
  information, possibly aiding in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = string("/Info.live.htm");

if(http_vuln_check(port:port, url:url, pattern:"\{lan_mac::", extra_check:make_list("\{wan_mac::","\{lan_ip::","\{lan_proto::"), usecache:TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
