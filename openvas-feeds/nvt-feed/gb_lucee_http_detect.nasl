# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146114");
  script_version("2024-03-07T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-03-07 05:06:18 +0000 (Thu, 07 Mar 2024)");
  script_tag(name:"creation_date", value:"2021-06-11 08:29:02 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Lucee Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Lucee.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default: 80);
host = http_host_name(dont_add_port: TRUE);

# nb: We need to call fetch404: TRUE on a few pages because on at least the "Error (missinginclude)"
# Lucee is throwing a 404 and we're not able to catch the error here.
url1 = "/";
res1 = http_get_cache(port: port, item: url1, fetch404: TRUE);

url2 = "/lucee/admin/server.cfm";
res2 = http_get_cache(port: port, item: url2);

url3 = "/lucee/templates/error/error.cfm";
res3 = http_get_cache(port: port, item: url3);

url4 = "/lucee/doc/index.cfm";
res4 = http_get_cache(port: port, item: url4);

url5 = "/index.cfm";
res5 = http_get_cache(port: port, item: url5, fetch404: TRUE);

url6 = "/lucee/admin/web.cfm";
res6 = http_get_cache(port: port, item: url6);

if (res1 =~ "^HTTP/1\.[01] 200" &&
    ("You are now successfully running Lucee" >< res1 ||
     res1 =~ "(X-Lucee-Version|X-CB-Server\s*:\s*LUCEE|X-IDG-Appserver\s*:\s*Lucee|CF_CLIENT_)")
   ) {
  found = TRUE;
  concUrl = "  " + http_report_vuln_url(port: port, url: url1, url_only: TRUE);
}

# nb: In case of any error state or similar like e.g.:
# class="label">Lucee 5.3.7.48 Error (expression)</td>
# class="label">Lucee 5.4.4.38 Error (missinginclude)</td>
# class="label">Lucee 5.3.4.45-SNAPSHOT Error (expression)</td>
if (res1 =~ "^HTTP/1\.[01] 404" && res1 =~ 'class="label">Lucee [0-9.]+[^<]* Error [^<]+</td>' ) {
  found = TRUE;
  concUrl = "  " + http_report_vuln_url(port: port, url: url1, url_only: TRUE);
}

# nb: Same as above for the "index.cfm"
if (res5 =~ "^HTTP/1\.[01] 404" && res5 =~ 'class="label">Lucee [0-9.]+[^<]* Error [^<]+</td>' ) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl += "  " + http_report_vuln_url(port: port, url: url5, url_only: TRUE);
}

if (("<title>Lucee Server Administrator" >< res2 && ("LuceeForms" >< res2 || "lucee.org" >< res2)) ||
    # nb: Same if e.g. no password is set yet:
    # <title>No Password set yet! - Lucee Server Administrator</title>
    ("Lucee Server Administrator</title>" >< res2 && ("LuceeForms" >< res2 || "lucee.org" >< res2))
   ) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl += "  " + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
}

# -lucee-err      { font-family: Verdana, Geneva, Arial, Helvetica, sans-serif; font-size: 11px;
# <table id="-lucee-err" cellpadding="4" cellspacing="1">
if ("lucee-err" >< res3) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl += "  " + http_report_vuln_url(port: port, url: url3, url_only: TRUE);
}

if ("<title>Lucee documentation" >< res4) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl += "  " + http_report_vuln_url(port: port, url: url4, url_only: TRUE);
}

if (res5 =~ "^HTTP/1\.[01] 200" &&
    ("You are now successfully running Lucee" >< res5 ||
     res5 =~ "(X-Lucee-Version|X-CB-Server\s*:\s*LUCEE|X-IDG-Appserver\s*:\s*Lucee|CF_CLIENT_)")
   ) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl = "  " + http_report_vuln_url(port: port, url: url5, url_only: TRUE);
}

if (("<title>Lucee Web Administrator" >< res6 && ("LuceeForms" >< res6 || "lucee.org" >< res6)) ||
    # nb: Same if e.g. no password is set yet:
    # <title>No Password set yet! - Lucee Web Administrator</title>
    ("Lucee Web Administrator</title>" >< res6 && ("LuceeForms" >< res6 || "lucee.org" >< res6))
   ) {
  found = TRUE;
  if (concUrl)
    concUrl += '\n';
  concUrl += "  " + http_report_vuln_url(port: port, url: url6, url_only: TRUE);
}

if (get_kb_item("www/" + host + "/" + port + "/lucee_error_vers_banner/detected")) {

  vers_banner_entries = get_kb_list("www/" + host + "/" + port + "/content/lucee_error_vers_banner");
  if (vers_banner_entries && is_array(vers_banner_entries)) {

    foreach vers_banner_entry (keys(vers_banner_entries)) {

      vers_banner_info = vers_banner_entries[vers_banner_entry];
      vers_banner_split = split(vers_banner_info, sep: "#----#", keep: FALSE);
      if (!vers_banner_split || max_index(vers_banner_split) != 2)
        continue;

      found = TRUE;

      vers_banner_concl = vers_banner_split[0];
      vers_banner_res = vers_banner_split[1];

      if (concUrl)
        concUrl += '\n';
      # nb: This is already the "full" URL
      concUrl += "  " + vers_banner_concl;

      # nb: Usually the first entry should be enough but only if it was a valid entry (checked by the continue() above)...
      break;
    }
  }
}

if (found) {

  version = "unknown";
  install = "/";
  # nb: Used multiple times below so this is only defined once here, e.g.:
  # class="label">Lucee 5.3.7.48 Error (expression)</td>
  # class="label">Lucee 5.4.4.38 Error (missinginclude)</td>
  # class="label">Lucee 5.3.4.45-SNAPSHOT Error (expression)</td>
  # class="label">Lucee 6.0.0.585-SNAPSHOT Error (missinginclude)</td>
  vers_error_page_pattern = ">Lucee ([0-9.]+)(-SNAPSHOT)? Error";

  set_kb_item(name: "lucee/detected", value: TRUE);
  set_kb_item(name: "lucee/http/detected", value: TRUE);

  # X-Lucee-Version: 5.3.8.139
  vers = eregmatch(pattern: "X-Lucee-Version\s*:\s*([0-9.]+)", string: res1);
  if (!isnull(vers[3]))
    version = vers[3];

  if (version == "unknown") {
    # You are now successfully running Lucee 5.2.9.31 on your system
    vers = eregmatch(pattern: "Lucee ([0-9.]+)(-SNAPSHOT)? on your system", string: res1);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    # nb: See examples above
    vers = eregmatch(pattern: vers_error_page_pattern, string: res3);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    # nb:
    # - Same as on "res3" can also happen on e.g. the "root" page ("/")
    # - See examples above
    vers = eregmatch(pattern: vers_error_page_pattern, string: res1);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    # nb:
    # - Same as on "res3" can also happen on e.g. the "index" page ("/index.cfm")
    # - See examples above
    vers = eregmatch(pattern: vers_error_page_pattern, string: res5);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    # <p class="lead-text">You are now successfully running Lucee 5.3.8.206 on your system!</p>
    # You are now successfully running Lucee 6.0.0.585 on your system
    vers = eregmatch(pattern: "Lucee ([0-9.]+)(-SNAPSHOT)? on your system", string: res5);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  if (version == "unknown") {
    # nb: See examples above
    vers = eregmatch(pattern: vers_error_page_pattern, string: vers_banner_res);
    if (!isnull(vers[1]))
      version = vers[1];
  }

  set_kb_item(name: "lucee/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + concUrl);
  set_kb_item(name: "lucee/detected", value: TRUE);
  set_kb_item(name: "lucee/http/detected", value: TRUE);
  set_kb_item(name: "lucee/http/port", value: port);
}

exit(0);
