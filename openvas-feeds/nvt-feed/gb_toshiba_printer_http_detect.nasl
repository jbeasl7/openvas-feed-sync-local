# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142906");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-09-18 03:01:18 +0000 (Wed, 18 Sep 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Toshiba Printer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  # nb: Don't use e.g. webmirror.nasl or DDI_Directory_Scanner.nasl as this VT should
  # run as early as possible so that the printer can be early marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Toshiba printer devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");
include("toshiba_printers.inc");

port = http_get_port(default: 8080);

urls = get_toshiba_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);

  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {

    model = "unknown";
    fw_version = "unknown";
    concl = "    " + match[0];
    conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    set_kb_item(name: "toshiba/printer/detected", value: TRUE);
    set_kb_item(name: "toshiba/printer/http/detected", value: TRUE);
    set_kb_item(name: "toshiba/printer/http/port", value: port);

    url2 = "/TopAccess/Device/Device.htm";
    res2 = http_get_cache(port: port, item: url2);

    mod = eregmatch(pattern: ">Copier Model.*>TOSHIBA ([^&]+)", string: res2);
    if (!isnull(mod[1])) {
      model = mod[1];
      concl += '\n    ' + mod[0];
      conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
    } else {
      cookie = http_get_cookie_from_header(buf: res, pattern: "(__secure-Session=[^;]+;)");
      if (isnull(cookie))
        cookie = http_get_cookie_from_header(buf: res, pattern: "(Session=[^;]+;)");

      if (!isnull(cookie)) {
        url2 = "/contentwebserver";
        data = "<DeviceInformationModel><GetValue><MFP><ModelName></ModelName></MFP></GetValue></DeviceInformationModel>";
        extra_cookie = "Locale=en-US,en#q=0.5;";
        if ("__secure-Session" >< cookie) {
          csrfpid = ereg_replace(pattern: "__secure-Session=(.*);", string: cookie, replace: "\1");
          extra_cookie = "__secure-Locale=en-US;";
        } else
          csrfpid = ereg_replace(pattern: "Session=(.*);", string: cookie, replace: "\1");

        # nb: It seems in some cases the csrfpId is not equal to the cookie and needs to be extracted separately
        # csrfInsert("csrfpId", "8pKe-d-Hp8-e4O6ienXkXE4NtKZXnQsZiY5d-Jt4nOM=");
        csrf_tag = eregmatch(pattern: 'csrfInsert\\("csrfpId", "([^"]+)"\\)', string: res);
        if (!isnull(csrf_tag[1]))
          csrfpid = csrf_tag[1];
        headers = make_array("Cookie", cookie += extra_cookie,
                             "csrfpId", csrfpid);

        req = http_post_put_req(port: port, url: url2, data: data, add_headers: headers);
        res2 = http_keepalive_send_recv(port: port, data: req);

        # <DeviceInformationModel><GetValue><MFP><ModelName>TOSHIBA e-STUDIO3005AC</ModelName></MFP></GetValue></DeviceInformationModel>
        mod = eregmatch(pattern: "<ModelName>TOSHIBA ([^<]+)<", string: res2);
        if (!isnull(mod[1])) {
          model = mod[1];
          concl += '\n    ' + mod[0];
          conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
        }

        # nb: Some printers do not expose this information so in order to avoid a 404 response also for model name we do two sepparate requests
        data = "<DeviceInformationModel><GetValue><Controller><Information/></Controller></GetValue></DeviceInformationModel>";
        req = http_post_put_req(port: port, url: url2, data: data, add_headers: headers);
        res2 = http_keepalive_send_recv(port: port, data: req);

        # <HDDataVersion>T330HD0W1281</HDDataVersion>
        vers = eregmatch(pattern: "<HDDataVersion>([^<]+)</HDDataVersion>", string: res2);
        if (!isnull(vers[1])) {
          fw_version = vers[1];
          concl += '\n    ' + vers[0];
          if (url2 >!< conclUrl)
            conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
        }
      } else {
        if (!isnull(match[1])) {

          # nb: No need to add this to the "concl" string as it was already added initially...
          model = match[1];

          url2 = "/cgi-bin/dynamic/printer/config/reports/deviceinfo.html";
          headers = make_array("Cookie", "lexlang=0;"); # language should be English as default language might differ. nb: Older firmware had shared the same code-base with Lexmark printers

          req = http_get_req(port: port, url: url2, add_headers: headers);
          res2 = http_keepalive_send_recv(port: port, data: req);

          # >Base</p></td><td><p> =  LW60.GM7.P632-0 </p></td>
          vers = eregmatch(pattern: '>Base</p></td><td><p> =  ([^ ]+)', string: res2);
          if (!isnull(vers[1])) {
            fw_version = vers[1];
            concl += '\n    ' + vers[0];
            conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
          } else {
            url2 = "/webglue/rawcontent?timedRefresh=1&c=Status&lang=en";
            res2 = http_get_cache(port: port, item: url2);
            # name":"DeviceFirmwareLevel","text":{"id":-1,"text":"MXTGM.073.023"}
            vers = eregmatch(pattern: '"name":"DeviceFirmwareLevel","text":\\{"id":[^,]+,"text":"([^"]+)"', string: res2);
            if (!isnull(vers[1])) {
              fw_version = vers[1];
              concl += '\n    ' + vers[0];
              conclUrl += '\n    ' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
            }
          }
        }
      }
    }

    set_kb_item(name: "toshiba/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "toshiba/printer/http/" + port + "/fw_version", value: fw_version);
    set_kb_item(name: "toshiba/printer/http/" + port + "/concluded", value: concl);
    set_kb_item(name: "toshiba/printer/http/" + port + "/concludedUrl", value: conclUrl);

    exit(0);
  }
}

exit(0);
