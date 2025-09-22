# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:fckeditor:fckeditor";

if(description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.117499");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2021-06-16 12:20:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("FCKeditor End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_fckeditor_http_detect.nasl");
  script_mandatory_keys("fckeditor/detected");

  script_tag(name:"summary", value:"The remote host is using the FCKeditor which is discontinued and
  will not receive any security updates.");

  script_tag(name:"vuldetect", value:"Checks if the target host is using a discontinued product.");

  script_tag(name:"impact", value:"A discontinued product is not receiving any security updates from
  the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to compromise the
  security of this host.");

  script_tag(name:"solution", value:"Replace FCKeditor with CKEditor which is still supported by the
  vendor.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("eol_shared.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! loc = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

report = eol_build_message( name:"FCKeditor",
                            cpe:CPE,
                            location:loc,
                            skip_version:TRUE,
                            eol_version:"All versions",
                            eol_date:"unknown",
                            eol_type:"prod" );
security_message( port:port, data:report );
exit( 0 );
