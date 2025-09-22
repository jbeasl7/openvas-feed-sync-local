# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103680");
  script_version("2024-07-12T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-07-12 05:05:45 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Dell DRAC / iDRAC Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell Remote Access Controller (DRAC) /
  Integrated Remote Access Controller (iDRAC).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 443);

# nb: iDRAC9
url = "/restgui/locale/personality/personality_en.json";
res1 = http_get_cache(port: port, item: url);

if (concl = egrep(string: res1, pattern: '"app_name"\\s*:\\s*"Integrated Remote Access Controller 9"', icase: FALSE)) {
  found = TRUE;
  concl = chomp(concl);
}

# nb: Sometimes the file above is empty / just returns "{}" so we can try to identify the system
# from another URL in addition to the previous
if (!found && res1 =~ "^HTTP/1\.[01] 200" && res1 =~ "Content-Type\s*:\s*application/json" && "{}" >< res1) {

  url = "/restgui/start.html";
  res2 = http_get_cache(port: port, item: url);

  # <idrac-start-screen config="settings" on-button-click="onBtnAction(action)" on-text-change="onChange(map)">
  # </idrac-start-screen>
  if (concl = eregmatch(string: res2, pattern: "<idrac-start-screen[^<]+</idrac-start-screen>", icase: FALSE)) {
    found = TRUE;
    concl = concl[0];
    # nb: Might have newlines so just replace them as it makes the reporting easier to read
    concl = str_replace(string: concl, find: '\n', replace: "");
  }
}

if (found) {

  fw_version = "unknown";
  fw_build = "unknown";
  idrac_generation = "unknown";
  server_generation = "unknown";

  concUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  concluded = "    " + concl;

  set_kb_item(name: "dell/idrac/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/" + port + "/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/port", value: port);

  url = "/sysmgmt/2015/bmc/info";
  req = http_get(port: port, item: url);
  res3 = http_keepalive_send_recv(port: port, data: req);

  # {"Attributes":{"ADEnabled":"Disabled","BuildVersion":"30","FwVer":"3.21.21.21","GUITitleBar":"iDRAC-71<redacted>","IsOEMBranded":"1","License":"Enterprise","SSOEnabled":"Disabled","SecurityPolicyMessage":"By accessing this computer, you confirm that such access complies with your organization's security policy.","ServerGen":"14G","SystemLockdown":"Disabled","SystemModelName":"Not Available","TFAEnabled":"Disabled","iDRACName":"iDRAC-71<redacted>"}}
  # {"Attributes":{"ADEnabled":"Disabled","BuildVersion":"32","FwVer":"4.10.10.10","GUITitleBar":"idrac-51<redacted>","IsOEMBranded":"0","License":"Enterprise","SSOEnabled":"Disabled","SecurityPolicyMessage":"By accessing this computer, you confirm that such access complies with your organization's security policy.","ServerGen":"15G","SystemLockdown":"Disabled","SystemModelName":"PowerEdge R6515","TFAEnabled":"Disabled","iDRACName":"idrac-51<redacted>"}}
  # {"Attributes":{"ADEnabled":"Disabled","BuildVersion":"21","FwVer":"3.36.36.36","GUITitleBar":"idrac-9W<redacted>","IsOEMBranded":"0","License":"Enterprise","SSOEnabled":"Disabled","SecurityPolicyMessage":"By accessing this computer, you confirm that such access complies with your organization's security policy.","ServerGen":"14G","SystemLockdown":"Disabled","SystemModelName":"PowerEdge R6415","TFAEnabled":"Disabled","iDRACName":"idrac-9W<redacted>"}}
  # {"Attributes":{"ADEnabled":"Disabled","BuildVersion":"34","FwVer":"4.20.20.20","GUITitleBar":"iDRAC-FV<redacted>","IsOEMBranded":"0","License":"Enterprise","SSOEnabled":"Disabled","SecurityPolicyMessage":"By accessing this computer, you confirm that such access complies with your organization's security policy.","ServerGen":"14G","SystemLockdown":"Disabled","SystemModelName":"PowerEdge T340","TFAEnabled":"Disabled","iDRACName":"iDRAC-FV<redacted>"}}
  fw_vers = eregmatch(pattern: '"FwVer"\\s*:\\s*"([0-9.]+)"', string: res3);
  if (!isnull(fw_vers[1])) {

    fw_version = fw_vers[1];

    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    concluded += '\n    ' + fw_vers[0];
  }

  server_gen = eregmatch(pattern: '"ServerGen"\\s*:\\s*"([^"]+)"', string: res3);
  if (!isnull(server_gen[1])) {

    server_generation = server_gen[1];

    concluded += '\n    ' + server_gen[0];

    # nb: Some systems didn't included the "FwVer" in the response so the concUrl might not have
    # been "filled" yet. Thus add the URL in this case for extended reporting.
    if (url >!< concUrl)
      concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  if (res1) {

    idrac_gen = eregmatch(string: res1, pattern: '"app_name"\\s*:\\s*"Integrated Remote Access Controller ([0-9]+)"', icase: FALSE);
    if (!isnull(idrac_gen[1])) {
      # nb: No need to add this to the "concluded" string as it might have been already added
      # previously
      idrac_generation = idrac_gen[1];
    }
  }

  set_kb_item(name: "dell/idrac/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "dell/idrac/http/" + port + "/fw_build", value: fw_build);
  set_kb_item(name: "dell/idrac/http/" + port + "/idrac_generation", value: idrac_generation);
  set_kb_item(name: "dell/idrac/http/" + port + "/server_generation", value: server_generation);

  if (concUrl)
    set_kb_item(name: "dell/idrac/http/" + port + "/concUrl", value: concUrl);

  if (concluded)
    set_kb_item(name: "dell/idrac/http/" + port + "/concluded", value: concluded);

  exit(0);
}

# nb: Some newer versions like iDRAC7/8 in between
url = "/login.html";
req = http_get_req(port: port, url: "/login.html", add_headers: make_array("Accept-Encoding", "gzip, deflate"));
res = http_keepalive_send_recv(port: port, data: req);

if ('<title id="titleLbl_id"></title>' >< res && "log_thisDRAC" >< res) {

  fw_version = "unknown";
  fw_build = "unknown";
  idrac_generation = "unknown";
  server_generation = "unknown";

  concUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "dell/idrac/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/" + port + "/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/port", value: port);

  url = "/session?aimGetProp=fwVersionFull";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  fw_vers = eregmatch(pattern: 'fwVersionFull"\\s*:\\s*"([^(" ]+)( \\(Build ([0-9]+)\\))?', string: res);
  if (!isnull(fw_vers[1])) {

    fw_version = fw_vers[1];

    if (!isnull(fw_vers[3]))
      fw_build = fw_vers[3];

    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    concluded = "    " + fw_vers[0];
  }

  # nb: Sometimes protected by auth so it's not possible to extract the "generation" in this case
  url = "/data?get=prodServerGen";
  req = http_post_put_req(port: port, url: url);
  res = http_keepalive_send_recv(port: port, data: req);

  server_gen = eregmatch(pattern: "<prodServerGen>([^<]+)", string: res);
  if (!isnull(server_gen[1])) {

    server_generation = server_gen[1];

    concUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    if (concluded)
      concluded += '\n';
    concluded += "    " + server_gen[0];
  }

  # nb:
  # - In case the URL above is access protected / not available we can try to grab the
  #   "Generation" from these images included on the login page
  # - For some reasons some iDRAC8 systems also had the Ttl_2_iDRAC7_Base_ML.png file so the
  #   iDRAC8 one needs to be tested first
  # - If adding an additional URL here make sure to also check the "if()" call in the code below
  #
  images = make_array(
     "/images/Ttl_2_iDRAC8_Base_ML.png", "8f8a11b24c183a5754b541ad9291545d",
     "/images/Ttl_2_iDRAC7_Base_ML.png", "d905b193de1434e771dae62912676028"
  );

  foreach imgurl (keys(images)) {

    imgmd5 = images[imgurl];

    # nb: At least on iDRAC8 not passing the "Accept-Encoding" header is causing a 404 when
    # requesting the image (for unknown reasons)
    imgreq = http_get_req(port: port, url: imgurl, add_headers: make_array("Accept-Encoding", "gzip, deflate"));
    imgres = http_keepalive_send_recv(port: port, data:imgreq, bodyonly: TRUE);
    if (imgres) {
      md5res = hexstr(MD5(imgres));
      if (md5res && md5res == imgmd5) {

        if ("iDRAC8" >< imgurl)
          idrac_generation = "8";
        else
          idrac_generation = "7";

        if (concluded)
          concluded += '\n';
        concluded += "    .png hash: " + md5res;

        concUrl += '\n    ' + http_report_vuln_url(port: port, url: imgurl, url_only: TRUE);

        break;
      }
    }
  }

  set_kb_item(name: "dell/idrac/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "dell/idrac/http/" + port + "/fw_build", value: fw_build);
  set_kb_item(name: "dell/idrac/http/" + port + "/idrac_generation", value: idrac_generation);
  set_kb_item(name: "dell/idrac/http/" + port + "/server_generation", value: server_generation);

  if (concUrl)
    set_kb_item(name: "dell/idrac/http/" + port + "/concUrl", value: concUrl);

  if (concluded)
    set_kb_item(name: "dell/idrac/http/" + port + "/concluded", value: concluded);

  exit(0);
}

# Testing for older versions
urls = make_array();

urls["/cgi/lang/en/login.xsl"] = "Dell Remote Access Controller ([0-9]{1})";
urls["/public/about.html"] = "Integrated Dell Remote Access Controller ([0-9]{1})";
urls["/cgi/about"] = "Dell Remote Access Controller ([0-9]{1})";
urls["/Applications/dellUI/Strings/EN_about_hlp.htm"] = "Integrated Dell Remote Access Controller ([0-9]{1})";

info_url[4] = make_list("/cgi/about");
info_url_regex[4] = make_list('var s_build = "([^"]+)"');

info_url[5] = make_list("/cgi-bin/webcgi/about");
info_url_regex[5] = make_list("<FirmwareVersion>([^<]+)</FirmwareVersion>");

info_url[6] = make_list("/public/about.html", "/Applications/dellUI/Strings/EN_about_hlp.htm");
info_url_regex[6] = make_list("Version ([^<]+)<br>", 'var fwVer = "([^"]+)";', "Version ([0-9.]+)");

info_url[7] = make_list("/public/about.html");
info_url_regex[7] = make_list('var fwVer = "([^("]+)";');

foreach url (keys(urls)) {

  req = http_get(item: url, port: port);
  buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
  if (!buf)
    continue;

  if (!egrep(pattern: urls[url], string: buf))
    continue;

  version = eregmatch(pattern: urls[url], string: buf);
  if (isnull(version[1]))
    continue;

  fw_version = "unknown";
  fw_build = "unknown";
  idrac_generation = "unknown";
  server_generation = "unknown";

  set_kb_item(name: "dell/idrac/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/" + port + "/detected", value: TRUE);
  set_kb_item(name: "dell/idrac/http/port", value: port);

  concUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  concluded = "    " + version[0];

  idrac_gen = version[1];
  if (!isnull(version[1]))
    idrac_generation = version[1];

  iv = int(version[1]);
  iv_urls = info_url[iv];

  if (iv_urls) {
    foreach iv_url (iv_urls) {
      req = http_get(item: iv_url, port: port);
      buf = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

      if (!buf || buf =~ "^HTTP/1\.[01] 404")
        continue;

      foreach iur (info_url_regex[iv]) {
        fw_vers = eregmatch(pattern: iur, string: buf);
        if (!isnull(fw_vers[1])) {
          fw_version = fw_vers[1];

          # nb: Only add if it is not included yet
          if (iv_url >!< concUrl)
            concUrl += '\n    ' + http_report_vuln_url(port: port, url: iv_url, url_only: TRUE);

          concluded += '\n    ' + fw_vers[0];
          break;
        }
      }

      if (fw_version) {
        if ("(Build" >< fw_version) {
          fw_vers = eregmatch(pattern: "^([0-9.]+)\(Build ([0-9]+)\)", string: fw_version);
          if (!isnull(fw_vers[1]))
            fw_version = fw_vers[1];

          if (!isnull(fw_vers[2]))
            fw_build = fw_vers[2];
        }
        break;
      }
    }
  }

  set_kb_item(name: "dell/idrac/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "dell/idrac/http/" + port + "/fw_build", value: fw_build);
  set_kb_item(name: "dell/idrac/http/" + port + "/idrac_generation", value: idrac_generation);
  set_kb_item(name: "dell/idrac/http/" + port + "/server_generation", value: server_generation);

  if (concUrl)
    set_kb_item(name: "dell/idrac/http/" + port + "/concUrl", value: concUrl);

  if (concluded)
    set_kb_item(name: "dell/idrac/http/" + port + "/concluded", value: concluded);
}

exit(0);
