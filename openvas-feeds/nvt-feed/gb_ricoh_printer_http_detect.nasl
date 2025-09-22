# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142810");
  script_version("2025-05-23T15:42:02+0000");
  script_tag(name:"last_modification", value:"2025-05-23 15:42:02 +0000 (Fri, 23 May 2025)");
  script_tag(name:"creation_date", value:"2019-08-28 04:38:13 +0000 (Wed, 28 Aug 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("RICOH Printer Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of RICOH printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("ricoh_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

urls = get_ricoh_detect_urls();

foreach url (keys(urls)) {
  model = "unknown";
  version = "unknown";
  web_version = "unknown";
  brand = "unknown";
  found = FALSE;
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");
  res = http_get_cache(item: url, port: port);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  match = eregmatch(pattern: pattern, string: res, icase: TRUE);
  if (!isnull(match[1])) {
    if (pattern == "/web/guest/([a-z]{2})/websys/webArch/mainFrame.cgi") {
      country_code = match[1];
      url = "/web/guest/" + country_code + "/websys/webArch/header.cgi";
      res = http_get_cache(port: port, item: url);
      if (res =~ "^HTTP/1\.[01] 200") {
        # nb: We are using this method instead of configuration.cgi due to localisation in some devices
        # <h2 id="modelName" style="z-index:1;">IM C2000</h2>
        # <h2 id="modelName" style="z-index:1;">MP C2004ex</h2>
        # <h2 id="modelName" style="z-index:1;">MP 305+</h2>
        # <h2 id="modelName" style="z-index:1;">Aficio MP 301</h2>
        # <h2 id="modelName" style="z-index:1;">Pro C5300S</h2>
        # <h2 id="modelName" style="z-index:1;">MP C4504 JPN</h2>
        mod = eregmatch(pattern: '<h2 id="modelName"[^>]+>((M|P|IP|IM|SP|MP|Pro|Aficio MP) [^ <]+)[^<]*</h2>', string: res);
        if (!isnull(mod[1])) {
          found = TRUE;
          model = chomp(mod[1]);
          concluded = '\n' + mod[0];
          concludedUrl = '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          br = eregmatch(pattern: '<div id="logo">\\s*<h1><img src="/images/([A-Z]+).gif"', string: res);
          # <div id="logo"><h1><img src="/images/LANIER.gif"
          # <div id="logo"><h1><img src="/images/RICOH.gif"
          # div id="logo"><h1><img src="/images/NRG.gif"
          if (!isnull(br[1])) {
            brand = br[1];
            concluded += '\n' + br[0];
          }
          url = "/web/guest/" + country_code + "/websys/status/configuration.cgi";
          res = http_get_cache(port: port, item: url);
          # <td nowrap align="">System</td><td nowrap>:</td><td nowrap>1.16</td>
          # <td nowrap align="">System</td>
          # <td nowrap>:</td>
          # <td nowrap>7.70</td>
          vers = eregmatch(pattern: ">System<[^:]+:<[^<]+<td nowrap>([0-9.]+)", string: res);
          if (!isnull(vers[1])) {
            version = vers[1];
            concluded += '\n' + vers[0];
            if (url >!< concludedUrl)
              concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          } else {
            # nb: This is a fallback for localized printers, eg. tw, ko
            #  <td nowrap>7.61</td>
            #  </tr>
            #  <tr class="staticProp">
            #  <td nowrap><img src="/images/settingBullet.gif" alt="" title=""></td>
            # <td nowrap align="">NIB</td>
            vers = eregmatch(pattern: '<td nowrap>([0-9.]+)</td>\\s*</tr>\\s*<tr class="staticProp">\\s*<td nowrap><img src[^>]+></td>\\s*<td nowrap align="">NIB</td>', string: res);
            if (!isnull(vers[1])) {
              version = vers[1];
              concluded += '\n' + vers[0];
              if (url >!< concludedUrl)
                concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
            }
          }
          # <td nowrap align="">Web Image Monitor</td>
          # <td nowrap>:</td>
          # <td nowrap>1.23</td>
          web_vers = eregmatch(pattern: ">Web Image Monitor<[^:]+:<[^<]+<td nowrap>([0-9.]+)", string: res);
          if (!isnull(web_vers[1]))
            web_version = web_vers[1];
        }
      }
    } else {
      model = chomp(match[1]);
      concluded = '\n' + match[0];
      concludedUrl = '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      found = TRUE;

      # Main&#32;Firmware&#32;Version</dt><dd>1.05</dd>
      vers = eregmatch(pattern: "Main&#32;Firmware&#32;Version</dt><dd>([.0-9]+)</dd>", string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n' + vers[0];
        if (url >!< concludedUrl)
          concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      } else {
        vers = eregmatch(pattern: "Main&#32;Firmware&#32;Version</dt><dd>([A-Z]{1,2})</dd>", string: res);
        if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n' + vers[0];
        if (url >!< concludedUrl)
          concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
        else {
          # >Firmware Version</td><td><span class="style1">:</span></td><td nowrap width="100%" >V1.04</td>
          vers = eregmatch(pattern: "Firmware Version</td>[^V]+V([0-9.]+)", string: res);
          if (!isnull(vers[1])) {
            set_kb_item(name: "ricoh_printer/http/" + port + "/fw_version", value: vers[1]);
            concluded += '\n' + vers[0];
            version = vers[1];
            if (url >!< concludedUrl)
              concludedUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          }
        }
      }
    }


    if (found) {
      set_kb_item(name: "ricoh/printer/detected", value:TRUE);
      set_kb_item(name: "ricoh/printer/http/detected", value:TRUE);
      set_kb_item(name: "ricoh/printer/http/port", value: port);
      set_kb_item(name: "ricoh/printer/http/" + port + "/model", value: model);
      set_kb_item(name: "ricoh/printer/http/" + port + "/brand", value: brand);
      set_kb_item(name: "ricoh/printer/http/" + port + "/concluded", value: concluded);
      set_kb_item(name: "ricoh/printer/http/" + port + "/concludedUrl", value: concludedUrl);
      set_kb_item(name: "ricoh/printer/http/" + port + "/fw_version", value: version);
      set_kb_item(name: "ricoh/printer/http/" + port + "/web_version", value: web_version);
      exit(0);
    }
  }
}

exit(0);
