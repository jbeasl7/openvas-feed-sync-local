# SPDX-FileCopyrightText: 2003-2004 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:horde:imp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11815");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Horde < 3.2.2 IMP_MIME_Viewer_html class XSS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003-2004 George A. Theall");
  script_family("Web application abuses");
  script_dependencies("imp_detect.nasl");
  script_mandatory_keys("horde/imp/detected");

  script_xref(name:"URL", value:"https://marc.info/?l=imp&m=105940167329471&w=2");
  script_xref(name:"URL", value:"https://marc.info/?l=imp&m=105981180431599&w=2");
  script_xref(name:"URL", value:"https://marc.info/?l=imp&m=105990362513789&w=2");

  script_tag(name:"solution", value:"Upgrade to Horde IMP version 3.2.2 or later or apply patches found
  in the announcements to imp/lib/MIME/Viewer/html.php.");

  script_tag(name:"summary", value:"The remote server is running at least one instance of Horde IMP whose
  version number is between 3.0 and 3.2.1 inclusive.");

  script_tag(name:"impact", value:"Such versions are vulnerable to several cross-scripting attacks whereby
  an attacker can cause a victim to unknowingly run arbitrary Javascript code simply by reading an HTML
  message from the attacker. Announcements of the vulnerabilities can be found at the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! info = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = info["version"];
path = info["location"];

if( ereg( pattern:"^3\.(0|1|2|2\.1)$", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
