# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103707");
  script_version("2025-01-22T08:32:30+0000");
  script_tag(name:"last_modification", value:"2025-01-22 08:32:30 +0000 (Wed, 22 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-05-08 11:31:24 +0100 (Wed, 08 May 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kyocera Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kyocera printer devices.");

  exit(0);
}

include("kyocera_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default: 80);

urls = kyocera_get_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");
  if ( "_pp.f_getPrinterModel = '([^']+)';" >< pattern) {
    req = http_get_req(port: port, url: url, add_headers: make_array("Cookie", "rtl=0; css=1"), referer_url: "/startwlm/Start_Wlm.htm");
    res = http_send_recv(port: port, data: req);
  } else {
    res = http_get_cache(item: url, port: port);
  }
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  # nb:
  # - Some TP-Link models are using the same so we are excluding them here for now because we can't
  #   maintain the "full" list of possible Kyocera models in the regex of kyocera_printers.inc.
  # - Keep the pattern in sync with the one in dont_print_on_printers.nasl
  #
  # e.g.:
  # </html><script type="text/javascript"> var modelName="Archer C5v"; var modelDesc="AC1200 Wireless Dual Band Gigabit VoIP Router"</script>
  # <script type="text/javascript"> var authTimes=0; var forbidTime=0; var modelName="TL-WR902AC"; var modelDesc="AC750 Wi-Fi Travel Router"; var forbidAdminLogin=0; var forbidUserLogin=0; var usernameIsAdmin=1;</script>
  # <a href="http://www.tp-link.com"><img id="logo" src="../img/login/top1_1.jpg" style="float: left;" border="0" /></a>
  # <label id="copyright">Copyright &copy; 2024 TP-LINK Corporation Limited. All rights reserved. </label>
  #
  if (res =~ '(var modelName="(TL-|Archer)["]+"|href="https?://www\\.tp-link\\.com"|TP-LINK Corporation Limited\\.)')
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "kyocera/printer/detected", value: TRUE);
    set_kb_item(name: "kyocera/printer/http/detected", value: TRUE);
    set_kb_item(name: "kyocera/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[1])) {
      model = match[1];
      set_kb_item(name: "kyocera/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "kyocera/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    url = "/dvcinfo/dvcconfig/DvcConfig_Config.htm";
    res = http_get_cache(port: port, item: url);

    # ComnAddLabelProperty('2',mes[193] + " :","2PJ_3F00.003.014","w272px");
    vers = eregmatch(pattern: "ComnAddLabelProperty\('2',mes\[193\][^,]+," + '"([^"]+)"', string: res);
    if (!isnull(vers[1])) {
      fw_version = vers[1];
      set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
      set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    } else {
      url = "/start/start.htm";
      res = http_get_cache(port: port, item: url);

      # sData[4] = "2MH_2F00.004.002";  // System Firmware
      vers = eregmatch(pattern: 'sData\\[[0-9]\\]\\s*=\\s*"([^"]+)";\\s*//\\s*System Firmware',
                       string: res);
      if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
      } else {
        url = "/js/jssrc/model/dvcinfo/dvcconfig/DvcConfig_Config.model.htm?arg1=0";
        req = http_get_req(port: port, url: url, add_headers: make_array("Cookie", "rtl=0"), referer_url: "/dvcinfo/dvcconfig/DvcConfig_Config.htm");
        res = http_send_recv(port: port, data: req);
        # _pp.system = '2V8_S000.002.232';
        vers = eregmatch(pattern: "_pp.system\s*=\s*'([^']+)'", string: res);
        if (!isnull(vers[1])) {
          fw_version = vers[1];
          set_kb_item(name: "kyocera/printer/http/" + port + "/versConcluded", value: vers[0]);
          set_kb_item(name: "kyocera/printer/http/" + port + "/versConcludedUrl",
                      value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
        }
      }
    }

    set_kb_item(name: "kyocera/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "kyocera/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

banner = http_get_remote_headers(port: port);

# e.g.:
# Server: KM-MFP-http/V0.0.1
# nb: Keep in sync with dont_print_on_printers.nasl and sw_http_os_detection.nasl
if (concl = egrep(pattern: "^Server\s*:\s*KM-MFP-http", string: banner, icase: TRUE)) {
  concl = chomp(concl);

  set_kb_item(name: "kyocera/printer/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/http/detected", value: TRUE);
  set_kb_item(name: "kyocera/printer/http/port", value: port);

  model = "unknown";
  fw_version = "unknown";

  set_kb_item(name: "kyocera/printer/http/" + port + "/model", value: model);
  set_kb_item(name: "kyocera/printer/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "kyocera/printer/http/" + port + "/generalConcluded", value: concl);
}

exit(0);
