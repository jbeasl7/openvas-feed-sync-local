# SPDX-FileCopyrightText: 2001 HD Moore & Drew Hintz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10811");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3526");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0815");
  script_name("ActivePerl perlIS.dll Buffer Overflow Vulnerability - Active Check");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("Copyright (C) 2001 HD Moore & Drew Hintz");
  script_family("Web application abuses");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_tag(name:"solution", value:"Either upgrade to a version of ActivePerl more
  recent than 5.6.1.629 or enable the 'Check that file exists' option.

  To enable this option, open up the IIS MMC, right click on a (virtual) directory in
  your web server, choose Properties, click on the Configuration... button, highlight
  the .plx item, click Edit, and then check/enable the 'Check that file exists' option.");

  script_tag(name:"summary", value:"An attacker can run arbitrary code on the remote computer.

  This is because the remote IIS server is running a version of ActivePerl prior to 5.6.1.630
  and has the Check that file exists option disabled for the perlIS.dll.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# nb: No get_app_location() as IIS is not "directly" affected and the initial version of
# this VT had only checked for the banner of IIS.
if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

function check(url) {

  req = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(!r)
    return(0);

  if(r =~ "^HTTP/1\.[01] 500" && ("The remote procedure call failed." >< r || "<html><head><title>Error</title>" >< r)) {
    security_message(port:port);
    return(1);
  }
  return(0);
}

foreach dir(make_list("/scripts/", "/cgi-bin/", "/")) {

  url = string(dir, crap(660), ".plx"); #by default perlIS.dll handles .plx
  if(check(req:url))
    exit(0);

  url = string(dir, crap(660), ".pl");
  if(check(req:url))
    exit(0);
}

exit(99);
