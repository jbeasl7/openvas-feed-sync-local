# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12221");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1977");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("3Com NBX VoIP NetSet Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.secnap.com/security/20040420.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10240");

  script_tag(name:"summary", value:"We have discovered that 3Com NBX VOIP NetSet is running
  on the remote host. 3Com NBX VoIP NetSet's web server is powered by VxWorks.");

  script_tag(name:"insight", value:"The web server is known to contain vulnerabilities that
  would allow a remote attacker to cause a denial of service against the product by simply
  running a port scanning/vulnerability scanning engine against it.");

  script_tag(name:"affected", value:"Problems have been observed in Netset 4.2.7, but previous
  4.1 versions seem to be ok.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

r = http_get_cache(item:"/", port:port);
if(!r)
  exit(0);

if("sysObjectID" >< r && "1.3.6.1.4.1.43.1.17" >< r) {
  security_message(port:port);
}

exit(0);
