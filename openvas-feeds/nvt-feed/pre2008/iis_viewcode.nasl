# SPDX-FileCopyrightText: 2000 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10576");
  script_version("2025-04-11T05:40:28+0000");
  script_cve_id("CVE-1999-0737");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft IIS Dangerous Default Files - Active Check");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2000 John Lampe");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"If you do not need these files, then delete them, otherwise
  use suitable access control lists to ensure that the files are not world-readable.");

  script_tag(name:"summary", value:"The file viewcode.asp is a default IIS files which can give a
  malicious user a lot of unnecessary information about your file system or source files.

  Specifically, viewcode.asp can allow a remote user to potentially read any file on a webserver
  hard drive.

  Example: http://example.com/pathto/viewcode.asp?source=../../../../../../autoexec.bat");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

urls = make_list(
"/Sites/Knowledge/Membership/Inspired/ViewCode.asp",
"/Sites/Knowledge/Membership/Inspiredtutorial/Viewcode.asp",
"/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp",
"/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp",
"/Sites/Samples/Knowledge/Push/ViewCode.asp",
"/Sites/Samples/Knowledge/Search/ViewCode.asp",
"/SiteServer/Publishing/viewcode.asp");

list = "";

foreach url(urls) {
  if(http_is_cgi_installed_ka(item:url, port:port)) {
    list = string(list, "\n", url);
  }
}

if(strlen(list)) {
  report = "The following files were found on the remote web server:" + list;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
