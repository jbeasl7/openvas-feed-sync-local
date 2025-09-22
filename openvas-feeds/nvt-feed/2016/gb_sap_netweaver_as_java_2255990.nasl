# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106149");
  script_version("2025-05-16T05:40:21+0000");
  script_tag(name:"last_modification", value:"2025-05-16 05:40:21 +0000 (Fri, 16 May 2025)");
  script_tag(name:"creation_date", value:"2016-07-22 14:30:27 +0700 (Fri, 22 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-20 19:49:00 +0000 (Tue, 20 Apr 2021)");

  script_cve_id("CVE-2016-3973");

  # nb: Current response check is not that reliable...
  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver AS Java Information Disclosure Vulnerability (2255990) - Active Check");

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

  script_tag(name:"summary", value:"SAP NetWeaver Application Server (AS) Java is prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the 'WD_CHAT'
  feature is accessible.

  Note: Multiple same / similar results of this VT are expected if multiple SAP products got
  detected on the same host and port.");

  script_tag(name:"insight", value:"The chat feature in the Real-Time Collaboration (RTC) services
  allows remote attackers to obtain sensitive user information.");

  script_tag(name:"impact", value:"An unauthenticated attacker can get information about SAP
  NetWeaver AS Java users.");

  script_tag(name:"affected", value:"SAP NetWeaver AS Java version 7.10 (7.1) through
  7.50 (7.5).");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://erpscan.io/advisories/erpscan-16-016-sap-netweaver-7-4-information-disclosure-wd_chat/");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/2255990");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

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

if (http_vuln_check(port: port, url: url, pattern: "^set-cookie\s*:", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
