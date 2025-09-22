# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnu:mailman";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16339");
  script_version("2025-04-25T15:41:53+0000");
  script_tag(name:"last_modification", value:"2025-04-25 15:41:53 +0000 (Fri, 25 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"OSVDB", value:"13671");

  script_cve_id("CVE-2005-0202");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mailman < 2.1.6b1 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("mailman_http_detect.nasl");
  script_mandatory_keys("gnu_mailman/detected");

  script_tag(name:"summary", value:"Mailman is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw comes into play only on web servers that don't strip
  extraneous slashes from URLs, such as Apache 1.3.x, and allows a list subscriber, using a
  specially crafted web request, to retrieve arbitrary files from the server - any file accessible
  by the user under which the web server operates, including email addresses and passwords of
  subscribers of any lists hosted on the server. For example, if '$user' and '$pass' identify a
  subscriber of the list '$listname@$target', then the following URL:

  http://example.com/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

  allows access to archives for the mailing list named 'mailman' for which the user might not
  otherwise be entitled.");

  script_tag(name:"solution", value:"Update to version 2.1.6b1 or later.");

  script_xref(name:"URL", value:"http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12504");
  script_xref(name:"URL", value:"http://lists.netsys.com/pipermail/full-disclosure/2005-February/031562.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = info["version"];
path = info["location"];

if( version_is_less_equal( version:vers, test_version:"2.1.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1.6b1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
