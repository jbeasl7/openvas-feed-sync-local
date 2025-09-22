# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813446");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2018-10658", "CVE-2018-10659", "CVE-2018-10660", "CVE-2018-10661",
                "CVE-2018-10662", "CVE-2018-10663", "CVE-2018-10664");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-06-19 15:06:09 +0530 (Tue, 19 Jun 2018)");
  script_name("Axis Network Camera Multiple Vulnerabilities (Jun 2018)");

  script_tag(name:"summary", value:"Axis Network Cameras is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and confirm
  the vulnerability from response.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Requests to a world-readable file that are followed by a backslash and end
    with the '.srv' extension (e.g. http://example.com/index.html/a.srv) are treated
    by the authorization code as standard requests to the index.html and thus
    granted access, while the requests are also treated as legitimate requests to
    an .srv path, and are thus handled by the .srv handler, simultaneously.

  - Legitimate requests that reach /bin/ssid's .srv functionality can choose one
    of several actions by setting the action parameter in the query-string of the
    request. One possible action is dbus, which allows the user to invoke any
    dbus request as root, without any restriction on the destination or content.
    Authorization mechanism that is intended to limit dbus request, PolicyKit, is
    configured to automatically grant access to requests originating from the root
    user.

  - The 'parhand ShellParser' does not sanitize special shell characters and also
    does not quote the parameter's values. Some of these parameters end up in
    configuration files in shell variable assignment format. These parameters are
    later used by shell init-scripts which run as a result of the setter command,
    that is executed when applying a new value for a parameter by running the
    sync command.

  - Insufficient sanitation of input passed via 'PATH_INFO' that ends with the
    '.srv' extension to a '.cgi' script.

  - Insufficient sanitation of 'return_page' and 'servermanager_return_page
    query-string parameters in /bin/ssid's .srv functionality.

  - An error in the 'libdbus-send.so' shared object triggered due to insufficient
    sanitation for crafted dbus-requests.

  - Insufficient sanitation of crafted command that can result in a code path
    that calls the UND undefined ARM instruction.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the web-server's authorization mechanism, conduct shell
  command injections, crash the httpd process, gain access to sensitive
  information, crash '/bin/ssid' process and get unrestricted dbus access for
  users of the '.srv' functionality.");

  script_tag(name:"affected", value:"Axis IP Cameras with more than 390 models are
  affected. Please see the references for a complete list.");

  script_tag(name:"solution", value:"Upgrade to latest firmware available from
  vendor. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");
  script_xref(name:"URL", value:"https://blog.vdoo.com/2018/06/18/vdoo-discovers-significant-vulnerabilities-in-axis-cameras");
  script_xref(name:"URL", value:"https://www.axis.com/files/sales/ACV-128401_Affected_Product_List.pdf");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9998);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

axport = http_get_port(default:80);

res = http_get_cache(item: "/", port: axport);

if('content="Axis Communications AB"' >< res && "<title>AXIS</title>" >< res)
{
  req = http_post_put_req( port:axport,
                       url:"/index.html/VT_TEST.srv",
                       data:'action=test&return_page=VT_Vulnerability_Test',
                       add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded"));

  res = http_keepalive_send_recv( port:axport, data:req);

  if(res =~ "^(HTTP/1.. 303)" && "Location:" >< res && "Location: VT_Vulnerability_Test" >< res)
  {
    report = http_report_vuln_url(port:axport, url:"/index.html/VT_TEST.srv");
    security_message(port:axport, data:report);
    exit(0);
  }
}

exit(0);
