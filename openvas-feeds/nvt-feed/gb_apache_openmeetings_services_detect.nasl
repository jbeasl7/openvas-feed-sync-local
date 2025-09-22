# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:openmeetings";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112074");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-10-09 11:54:21 +0200 (Mon, 09 Oct 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache OpenMeetings Web Services Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_apache_openmeetings_http_detect.nasl");
  script_require_ports("Services/www", 5080);
  script_mandatory_keys("apache/openmeetings/http/detected");

  script_tag(name:"summary", value:"This host is running Apache OpenMeetings, a software used for
  presenting, online training, web conferencing, collaborative whiteboard drawing and document
  editing, and user desktop sharing.");

  script_xref(name:"URL", value:"https://openmeetings.apache.org/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/services/services";

req = http_get(item: url, port: port);
buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

if("/services/services" >< buf && "Service list" >< buf) {
  report = 'The following services were detected at ' + http_report_vuln_url(url: url, port: port, url_only: TRUE) + ' :\n';
  found_service = FALSE;

  #SOAP
  if ("Available SOAP services" >< buf) {
    soap_sep = '?wsdl">';
    soap_pattern = '<a href="(.*)\\?wsdl">';

    services = egrep(string: buf, pattern: soap_pattern, icase: TRUE);

    if(services) {
      report += '\nSOAP Services:\n';

      foreach service(split(services, sep: soap_sep)) {
        service_url = eregmatch(string: service, pattern: soap_pattern, icase: TRUE);

        if(!isnull(service_url[1])) {
          service_name = eregmatch(string: service_url[1], pattern:"services\/(.*)", icase: TRUE);

          set_kb_item(name:"openmeetings/services", value:service_name[1]);
          report = report + '\nName: ' + service_name[1] + '\nWSDL: ' + service_url[1] + '?wsdl\n';
          found_service = TRUE;
        }
      }
    }
  }

  # REST
  if("Available RESTful services" >< buf) {
    rest_sep = '?_wadl">';
    rest_pattern = '<a href="(.*)\\?_wadl">';

    services = eregmatch(string: buf, pattern: 'Available RESTful services(.*)', icase: TRUE);

    if(services[1]) {
      report += '\n\nREST Services:\n';

      foreach service(split(services[1], sep: rest_sep)) {
        service_url = eregmatch(string: service, pattern: rest_pattern, icase: TRUE);

        if(!isnull(service_url[1])) {
          report = report + '\nWADL: ' + service_url[1] + '?_wadl\n';
          found_service = TRUE;
        }
      }
    }
  }

  if(found_service)
    log_message(data: report, port: port);
}

exit(0);
