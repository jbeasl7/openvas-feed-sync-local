# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114088");
  script_version("2022-08-26T10:12:16+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-26 10:12:16 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-03-28 12:23:30 +0100 (Thu, 28 Mar 2019)");
  script_name("CAREL pCOWeb Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 10000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of CAREL's pCOWeb management software for
  various devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("cpe.inc");

port = http_get_port(default: 10000);
host = http_host_name(dont_add_port: TRUE);

url1 = "/";
res1 = http_get_cache(port: port, item: url1);

if(
    # nb: Standard system
    ("Carel pCOWeb Home Page" >< res1 && "<h2>This page will be redirected <a href" >< res1 && "location=" >< res1) ||
    # nb: Seen on "RDZ pCOWeb Application" devices
    ("<title>Initial Home Page</title>" >< res1 && 'This page will be redirected <a href "./http/index.html">here' >< res1 && 'location="./http/index.html";' >< res1) ||
    # nb: Rescue mode if the device is "broken", the <h> tag was inconsistent so this has been left out:
    # <H1>This is the "Carel pCOWeb" Rescue Home Page</h1>
    "<title>Carel pCOWeb Rescue Home Page</title>" >< res1 || '>This is the "Carel pCOWeb" Rescue Home Page</' >< res1
  ) {

  install = "/";
  version = "unknown";
  appName = "CAREL pCOWeb Device";
  cpe = "cpe:/h:carel:pcoweb_card:";
  default_cpe = cpe;
  set_kb_item(name: "carel/pcoweb/device/detected", value: TRUE);
  set_kb_item(name: "carel/pcoweb/device/http/detected", value: TRUE);

  conclUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

  url2 = "/http/index.html";
  res2 = http_get_cache(port: port, item: url2);

  if("Rehau" >< res2 && "URL=default.html" >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    appName = "CAREL pCOWeb Rehau Group Temperature Control System";
    set_kb_item(name: "carel/pcoweb/rehau/temperature_controller/detected", value: TRUE);
    set_kb_item(name: "carel/pcoweb/rehau/temperature_controller/http/detected", value: TRUE);

    verUrl = "/http/hc/SysInfo.html";
    req3 = http_get_req(port: port, url: verUrl); #Due to the huge size of the response,
    res3 = http_send_recv(port: port, data: req3); #this function is being used to fully receive it.

    #The bios version needs to be stitched together piece by piece, due to being all over the place.
    #An example version would be 6.27
    #(one regex for both, using '|' didn't seem to work in NASL)
    biosMajor = eregmatch(pattern: '"versionBios"\\s*[^>]+>[^;]+;([0-9]+).', string: res3, icase: TRUE);
    biosMinor = eregmatch(pattern: "var\s*biosMinor\s*=parseInt\(([0-9]+)\);", string: res3, icase: TRUE);
    if(!isnull(biosMajor[1])) {

      conclUrl += '\n' + http_report_vuln_url(port: port, url: verUrl, url_only: TRUE);

      #Also reconstruct the version if only "6" was found in the example.
      if(isnull(biosMinor[1])) {
        version = biosMajor[1];
        conclVer = biosMajor[0];
      } else {
        version = biosMajor[1] + "." + biosMinor[1];
        conclVer = biosMajor[0] + '\n' + biosMinor[0];
      }
    }
    cpe = "cpe:/h:carel:pcoweb_rehau_temperature_controller:";

  } else if("RDZ pCOWeb Application" >< res2 && 'location="/http/rdz/index.html";' >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    appName = "CAREL pCOWeb RDZ Controller";
    set_kb_item(name: "carel/pcoweb/rdz/controller/detected", value: TRUE);
    set_kb_item(name: "carel/pcoweb/rdz/controller/http/detected", value: TRUE);

    verUrl = "/http/rdz/application.html";
    req3 = http_get_req(port: port, url: verUrl);
    res3 = http_send_recv(port: port, data: req3); # nb: Due to the huge size of the response, this function is being used to fully receive it.

    #Ver. 2.2.0</div>
    ver = eregmatch(pattern: "Ver.\s*([0-9.]+)</div>", string: res3, icase: TRUE);
    if(!isnull(ver[1])) {
      conclUrl += '\n' + http_report_vuln_url(port: port, url: verUrl, url_only: TRUE);
      version = ver[1];
      conclVer = ver[0];
    }
    cpe = "cpe:/h:carel:pcoweb_rdz_controller:";

  } else if("pCOWeb Default Page" >< res2 || "This is the default index.html provided by Carel Industries S.r.l." >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    #This one is worth detecting on its own, due to the availability of default credentials.
    appName = "CAREL pCOWeb Default Page";
    set_kb_item(name: "carel/pcoweb/default_page/detected", value: TRUE);
    set_kb_item(name: "carel/pcoweb/default_page/http/detected", value: TRUE);

    cpe = "cpe:/a:carel:pcoweb_default_page:";

  } else if("function getVariables() {" >< res2 && "getParams('/usr-cgi/xml.cgi'" >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    appName = "CAREL pCOWeb GSI Heat Pump";
    set_kb_item(name: "carel/pcoweb/gsi/heat_pump/detected", value: TRUE);
    set_kb_item(name: "carel/pcoweb/gsi/heat_pump/http/detected", value: TRUE);

    cpe = "cpe:/h:carel:pcoweb_gsi_heat_pump:";

  } else if("function WriteALR()" >< res2 && "function WebDate()" >< res2 && "function WebHour()" >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    appName = "CAREL pCOWeb Nalon Heat Pump";
    set_kb_item(name: "carel/pcoweb/nalon/heat_pump/detected", value: TRUE);
    set_kb_item(name: "carel/pcoweb/nalon/heat_pump/http/detected", value: TRUE);

    cpe = "cpe:/h:carel:pcoweb_nalon_heat_pump:";
  } else {

    #Some Glen Dimplex devices are only reachable directly via their /http/index/j_*.html pages.
    glenUrl = "/http/index/j_operatingdata.html";
    req3 = http_get_req(port: port, url: glenUrl);
    res3 = http_send_recv(port: port, data: req3); # nb: Due to the huge size of the response, this function is being used to fully receive it.

    if(("function vorlader()" >< res2 && '<body onLoad="vorlader()">' >< res2 || "<script>var bios" >< res3 && "<script>var boot" >< res3) ||
       ("<!-- Temperatur Speicher" >< res3 && "<!-- Vorlauftemperatur" >< res3)) {

      conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
      conclUrl += '\n' + http_report_vuln_url(port: port, url: glenUrl, url_only: TRUE);

      appName = "CAREL pCOWeb Glen Dimplex Brine/Air To Water Heat Pump";
      set_kb_item(name: "carel/pcoweb/glen_dimplex/heat_pump/detected", value: TRUE);
      set_kb_item(name: "carel/pcoweb/glen_dimplex/heat_pump/http/detected", value: TRUE);

      #<script>var bios = 62.7; -> is only later converted to "6.27" for some reason through "Math.round(bios*10)/100"
      #As NASL can't handle floating point arithmetic, we have to manually stitch the version pieces together.
      biosVer = eregmatch(pattern: "<script>var bios\s*=\s*([0-9]*)([0-9]).([0-9]+);", string: res3, icase: TRUE);

      #The biosVer[1] component is optional (The important part is the first number to the left of the comma).
      #The logical equation is as follows:
      #If A is biosVer[1], B is biosVer[2] and C is biosVer[3] => (B && C) || (A && B && C)
      if((!isnull(biosVer[2]) && !isnull(biosVer[3]) ) || (!isnull(biosVer[1]) && !isnull(biosVer[2]) && !isnull(biosVer[3]))) {
        version = biosVer[1] + "." + biosVer[2] + biosVer[3];
        conclVer = biosVer[0];
      }

      cpe = "cpe:/h:carel:pcoweb_glen_dimplex_heat_pump:";
    }
  }

  # nb: Basic auth check for default_http_auth_credentials.nasl
  foreach url(make_list("/http/index.html", "/http/main.html")) {
    res = http_get_cache(item: url, port: port);
    if(res && res =~ "^HTTP/1\.[01] 401") {
      set_kb_item(name: "www/content/auth_required", value: TRUE);
      set_kb_item(name: "www/" + host + "/" + port + "/content/auth_required", value: url);
    }
  }

  # nb: We also always want to register the "base" / default CPE for generic active VTs to be able
  # to run the active VTs against all "branded" devices or similar.
  if(cpe != default_cpe)
    register_product(cpe: default_cpe, location: install, port: port, service: "www");

  register_and_report_cpe(app: appName,
                          ver: version,
                          concluded: conclVer,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
