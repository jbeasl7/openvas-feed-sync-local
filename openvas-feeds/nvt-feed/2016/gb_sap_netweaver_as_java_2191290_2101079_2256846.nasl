# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106083");
  script_version("2025-05-14T05:40:11+0000");
  script_tag(name:"last_modification", value:"2025-05-14 05:40:11 +0000 (Wed, 14 May 2025)");
  script_tag(name:"creation_date", value:"2016-05-23 10:42:10 +0700 (Mon, 23 May 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 19:30:00 +0000 (Tue, 20 Apr 2021)");

  script_cve_id("CVE-2016-1910", "CVE-2016-2386", "CVE-2016-2388");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver AS Java Multiple Vulnerabilities (2101079, 2191290, 2256846) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web Servers");
  # nb: See notes below on the reason of this dependency chain
  script_dependencies("gb_sap_netweaver_as_java_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_sap_netweaver_as_icm_http_detect.nasl",
                        "gsf/gb_sap_web_dispatcher_http_detect.nasl",
                        "gsf/gb_sap_icf_http_detect.nasl",
                        "gsf/gb_sap_netweaver_portal_http_detect.nasl",
                        "gsf/gb_sap_netweaver_as_http_detect.nasl");
  script_mandatory_keys("sap/products/http/detected");

  script_tag(name:"summary", value:"SAP NetWeaver Application Server (AS) Java is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.

  Note: Multiple same / similar results of this VT are expected if multiple SAP products got
  detected on the same host and port.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2016-1910: The User Management Engine (UME) allows attackers to decrypt unspecified data via
  unknown vectors.

  - CVE-2016-2386: SQL injection vulnerability in the UDDI server.

  - CVE-2016-2388: The Universal Worklist Configuration allows remote attackers to obtain sensitive
  user information via a crafted HTTP request.");

  script_tag(name:"impact", value:"A remote attacker may execute arbitrary SQL commands or obtain
  sensitive user information via a crafted HTTP request.");

  script_tag(name:"affected", value:"SAP NetWeaver AS Java version 7.10 (7.1) through 7.50 (7.5).");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2101079");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2191290");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2256846");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39841/");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43495/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# nb: Reasons for this CPE list:
# - NetWeaver AS Java is actually affected
# - NetWeaver Portal is running on NetWeaver AS Java as well
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
# results is acceptable and covered via a note in the vuldetect tag.
if (!infos = get_app_port_from_list(cpe_list: cpe_list, service: "www", first_cpe_only: FALSE))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if (!dir = get_app_location(cpe: cpe, port: port))
  exit(0);

if (dir == "/" || dir =~ "^[0-9]+/tcp$") # nb: gb_sap_netweaver_as_http_detect.nasl is setting e.g. 443/tcp
  dir = "";

url = dir + "/webdynpro/resources/sap.com/tc~rtc~coll.appl.rtc~wd_chat/Chat";

# nb: NetWeaver seems sometimes to check the 'User-Agent'
req = http_get_req(port: port, url: url, user_agent: "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.19) Gecko/20110420 Firefox/3.5.19");
res = http_keepalive_send_recv(port: port, data: req);

if ("Add Participant" >< res && "<title>Instant Messaging</title>" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
