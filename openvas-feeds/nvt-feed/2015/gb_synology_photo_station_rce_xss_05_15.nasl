# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:synology:synology_photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105280");
  script_cve_id("CVE-2015-4656");
  script_version("2023-10-27T05:05:28+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Synology Photo Station Command Injection and multiple Cross Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20150504/synology_photo_station_multiple_cross_site_scripting_vulnerabilities.html");
  script_xref(name:"URL", value:"https://www.securify.nl/advisory/SFY20150502/command_injection_vulnerability_in_synology_photo_station.html");

  script_tag(name:"insight", value:"Multiple errors exist due to insufficient
 validation of input passed via 'success' parameter to login.php script, 't'
 parameter to /photo/index.php script and 'description' POST parameter to
 photo.php script.");

  script_tag(name:"impact", value:"An attacker may leverage the XSS issues to
execute arbitrary script code in the browser of an unsuspecting user in the context
of the affectedasite. This may allow the attacker to steal cookie-based
authentication credentials and launch other attacks.

The Command Injection vulnerability allows an attacker to execute arbitrary commands
with the privileges of the webserver. An attacker can use this vulnerability to
compromise a Synology DiskStation NAS, including all data stored on the NAS.");

  script_tag(name:"vuldetect", value:"Send a crafted http GET request and check if it
is possible to read cookie or not.");
  script_tag(name:"solution", value:"Update to 6.3-2945 or newer.");
  script_tag(name:"summary", value:"Synology Photo Station is prone to a command
injection vulnerability and multiple cross-site scripting vulnerabilities
because it fails to sanitize user-supplied input.");

  script_tag(name:"affected", value:"Photo Station 6 < 6.3-2945");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"last_modification", value:"2023-10-27 05:05:28 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-05-26 14:30:57 +0200 (Tue, 26 May 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_synology_photo_station_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("synology_photo_station/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!photoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:photoPort)){
  exit(0);
}

url = dir + "/m/login.php?success=%3E%3Cscript%3Ealert%28documen" +
            "t.cookie%29%3C/script%3E";

if(http_vuln_check(port:photoPort, url:url, pattern:"<script>alert\(document.cookie\)</script>",
   extra_check: make_list(">Photo Station<", ">Synology"), check_header:TRUE))
{
  report = http_report_vuln_url( port:photoPort, url:url );
  security_message(port:photoPort, data:report);
  exit(0);
}

exit(99);
