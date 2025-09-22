# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808730");
  script_version("2025-09-12T15:39:53+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-12 15:39:53 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-08-01 13:52:04 +0530 (Mon, 01 Aug 2016)");

  script_name("Liferay Portal/DXP Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Liferay Portal/DXP.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Liferay Admin User", value:"", type:"entry", id: 1);
  script_add_preference(name:"Liferay Admin Password", value:"", type:"password", id: 2);

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 443);

foreach dir(make_list_unique("/", "/Liferay", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/";

  res = http_get_cache(port: port, item: url);

  if (res !~ "^HTTP/1\.[01] (200|30.)" || ("Liferay-Portal:" >!< res &&
       "X-Liferay-Request" >!< res)) {
    url = dir + "/web/guest";
    res = http_get_cache(port: port, item: url);
  }

  if (res =~ "^HTTP/1\.[01] (200|30.)" && ("Liferay-Portal:" >< res ||
     "X-Liferay-Request" >< res)) {

    set_kb_item(name: "liferay/detected", value: TRUE);
    set_kb_item(name: "liferay/http/detected", value: TRUE);
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
    version = "unknown";
    update = "";
    # Liferay Community Edition Portal 7.0.1 GA2 (Wilberforce / Build 7001 / June 10, 2016)
    # Liferay Portal Community Edition 6.2 CE GA6 (Newton / Build 6205 / January 6, 2016)
    # Liferay DXP Digital Enterprise 7.0.10 GA1 (Wilberforce / Build 7010 / June 15, 2016)
    # Liferay Portal Enterprise Edition 6.2.10 EE GA1 (Newton / Build 6210 / November 1, 2013)
    # Liferay Enterprise Portal 4.3.4 (Owen / Build 4304 / November 5, 2007)
    # Liferay Digital Experience Platform 7.1.10 GA1 (Judson / Build 7110 / July 2, 2018)
    # Liferay Digital Experience Platform 7.3.10 GA1 (Athanasius / Build 7310 / September 22, 2020)
    # Liferay Portal Standard Edition 5.2.3 (Augustine / Build 5203 / May 20, 2009)
    #
    # nb: It's also possible to not expose the version info:
    # Liferay Digital Experience Platform
    vers = eregmatch(pattern: "Liferay-Portal: (Liferay ([a-zA-Z ]+)([0-9.]+)?)( (CE|EE|DE|DXP))?( ([GA0-9]+))?( \(([a-zA-Z]+ / Build [0-9]+ / [a-zA-Z]+ [0-9]+, [0-9]+)\))?",
                     string: res);

    if (!isnull(vers[3])) {
      version = vers[3];
    }

    if (!isnull(vers[7])) {
      # e.g. 7.0.10.GA1
      version += "." + vers[7];
    }

    if (!isnull(vers[2])) {
      edition = chomp(vers[2]);
      set_kb_item(name: "liferay/" + port + "/edition", value: edition);
      concluded = vers[0];
    } else {
      # nb: In cases where the detection was done via the X-Liferay-Request headers, this is
      # the only indicator of the edition that is present
      if ("Liferay-DXP-EULA" >< res) {
        edition = "DXP";
      }
    }

    if (!isnull(vers[9]))
      extra = "Build details: " + vers[9];

    url = dir + "/api/jsonws";
    res2 = http_get_cache(port: port, item: url);
    if (res2 && ("<title>json-web-services-api</title>" >< res2 || "JSONWS API" >< res2)) {
      if (extra)
        extra += '\n';
      extra += "JSONWS API:    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }

    if (version == "unknown") {
      user = script_get_preference("Liferay Admin User", id: 1);
      pass = script_get_preference("Liferay Admin Password", id: 2);

      if( ! user && ! pass ) {
        if (extra)
          extra += '\n';
        extra += "Note: No admin user and password credentials for web authentication were provided. Please provide these for version extraction.";
      } else if( ! user && pass ) {
        if (extra)
          extra += '\n';
        extra += "Note: Password for web authentication was provided but Admin User is missing.";
      } else if( user && ! pass ) {
        if (extra)
          extra += '\n';
        extra += "Note: Admin User for web authentication was provided but Password is missing.";
      } else if( user && pass ) {
        cookie = http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID[^;]+)");
        extra_cookie = "";
        cookie2 = http_get_cookie_from_header(buf: res, pattern: "(COOKIE_SUPPORT[^;]+)");
        if (cookie2)
          extra_cookie += cookie2;

        cookie2 = http_get_cookie_from_header(buf: res, pattern: "(GUEST_LANGUAGE_ID[^;]+)");
        if (cookie2)
          extra_cookie += "; " + cookie2;

        if (extra_cookie)
          cookie += "; " + extra_cookie;
        cookie += ";";
        #   Liferay.authToken = 'qJIt0zYD';
        tok = eregmatch(pattern: "Liferay\.authToken\s*=\s*'([^']+)';", string: res);
        if (tok[1])
          csfr_token = tok[1];

        headers = make_array("Cookie", cookie);
        url = dir + "/home?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=0&" +
              "p_p_state=exclusive&p_p_mode=view&_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=" +
              "%2Flogin%2Flogin&saveLastPath=false";

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);
        if (res =~ "^HTTP/(1\.[01]|2) (200|302)") {

          new_cookie = http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID[^;]+)");
          if (new_cookie) {
            cookie = new_cookie;
            if (extra_cookie)
              cookie += "; " + extra_cookie;
            cookie += ";";
          }
          # nb: p_auth is used in both DXP and Portal, but different
          p_auth = eregmatch(pattern: 'p_auth=([^"\']+)', string: res);

          if (p_auth[1]) {
            base_url = dir + "/home";
            # In the case of Liferay DXP 7.4.3, it seems the Jakarta one is used
            variable_param = "_com_liferay_login_web_portlet_LoginPortlet_javax.portlet.action";
            if ("_com_liferay_login_web_portlet_LoginPortlet_jakarta" >< res)
              variable_param = "_com_liferay_login_web_portlet_LoginPortlet_jakarta.portlet.action";
            url_params = "?p_p_id=com_liferay_login_web_portlet_LoginPortlet&p_p_lifecycle=1&p_p_state=exclusive&" +
                  "p_p_mode=view&" + variable_param + "=%2Flogin%2Flogin&" +
                  "_com_liferay_login_web_portlet_LoginPortlet_mvcRenderCommandName=%2Flogin%2Flogin";
            # nb: Portal needs the p_auth as URL parameter
            if (edition !~ "Digital Experience Platform" && edition !~ "DXP")
              url_params += "&p_auth=" + p_auth[1];
            url = base_url + url_params;
            if (!csfr_token)
              csfr_token = p_auth[1];

            headers = make_array("Cookie", cookie,
                                 "x-csrf-token", csfr_token,
                                 "x-requested-with", "XMLHttpRequest",
                                 "Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryn8oOmfEeVuBPsWvz");
            data = '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="' +
                   '_com_liferay_login_web_portlet_LoginPortlet_formDate"\r\n\r\n' + unixtime() + '\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_saveLastPath"\r\n\r\nfalse\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_redirect"\r\n\r\n\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_doActionAfterLogin"\r\n\r\nfalse\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_login"\r\n\r\n' + user +'\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_password"\r\n\r\n' + pass +'\r\n' +
            '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="_com_liferay_login_web_portlet_LoginPortlet_checkboxNames"\r\n\r\nrememberMe\r\n';
            # nb: DXP needs the p_auth as part of the POST data
            if (edition =~ "Digital Experience Platform" || edition =~ "DXP")
              data +=  '------WebKitFormBoundaryn8oOmfEeVuBPsWvz\r\nContent-Disposition: form-data; name="p_auth"\r\n\r\n' + p_auth[1] + '\r\n';
            data += '------WebKitFormBoundaryn8oOmfEeVuBPsWvz--\r\n';
            req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
            res = http_keepalive_send_recv(port: port, data: req);

            if (res =~ "^HTTP/(1\.[01]|2) (200|302)") {
              cookie = extra_cookie;
              cookie += "; " + http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID[^;]+)");
              company_id = http_get_cookie_from_header(buf: res, pattern: "(COMPANY_ID[^;]+)");
              if (company_id)
                cookie += "; " + company_id;
              c_id = http_get_cookie_from_header(buf: res, pattern: "(ID[^;]+)");
              if (c_id)
                cookie += "; " + c_id;
              cookie += ";";
              headers = make_array("Cookie", cookie,
                                   "x-csrf-token", csfr_token,
                                   "x-requested-with", "XMLHttpRequest");
              url = dir + "/group/guest/~/control_panel/manage?p_p_id=com_liferay_server_admin_web_portlet_ServerAdminPortlet&p_p_lifecycle=0&p_p_state=maximized&p_v_l_s_g_id=20117";
              req = http_get_req(port: port, url: url, add_headers: headers);

              res = http_keepalive_send_recv(port: port, data: req);

              # <strong>Info</strong>: Liferay Community Edition Portal 7.4.3.132 CE GA132 (February 18, 2025)
              # <strong>Info</strong>: Liferay Digital Experience Platform 2025.Q1.17 LTS (September 05, 2025)
              # <strong>Info</strong>: Liferay Digital Experience Platform 7.4.13 Update 140 (September 12, 2025)
              if (res =~ "^HTTP/(1\.[01]|2) (200|302)") {
                vers = eregmatch(pattern: "<strong>Info</strong>: (Liferay ([a-zA-Z ]+)([0-9qQ.]+)?)( (CE|EE|DE|DXP|LTS))?( ([GA0-9]+))?( Update ([0-9]+))?",
                                 string: res);

                if (!isnull(vers[3])) {
                  version = vers[3];
                  # e.g. 7.0.10.GA1
                  # 7.4.3.132.GA132
                  if (!isnull(vers[7]))
                    version += "." + vers[7];

                  if (!isnull(vers[8]))
                    version += vers[8];
                  conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
                  concluded += '\n' + vers[0];
                }
                if (!isnull(vers[2]))
                  edition = chomp(vers[2]);
              }
            }
          }

        }
      }
    }

    set_kb_item(name: "liferay/http/port", value: port);
    set_kb_item(name: "liferay/http/" + port + "/installs",
                value: port + "#---#" + edition + "#---#" + install + "#---#" +
                version + "#---#" + concluded + "#---#" + conclUrl + "#---#" + extra);
    exit(0);
  }
}

exit(0);
