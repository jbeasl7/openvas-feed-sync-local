# SPDX-FileCopyrightText: 2003 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11776");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2729");
  script_cve_id("CVE-2001-0614");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Carello.dll <= 1.3 Command Execution Vulnerability");
  script_category(ACT_ATTACK); # nb: Direct access to a .dll file might be already seen as an attack
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version if necessary.");

  script_tag(name:"summary", value:"Carello.dll was found on the remote web server.");

  script_tag(name:"insight", value:"Versions up to 1.3 of this web shopping cart allowed
  anybody to run arbitrary commands on your server.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

res = http_is_cgi_installed_ka( item:"Carello.dll", port:port );
if( res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 0 );
