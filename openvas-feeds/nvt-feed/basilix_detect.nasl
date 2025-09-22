# SPDX-FileCopyrightText: 2005 George A. Theall
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14308");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BasiliX Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2005 George A. Theall");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/basilix/");

  script_tag(name:"summary", value:"HTTP based detection of BasiliX.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:80);

if (!http_can_host_php(port:port))
  exit(0);

host = http_host_name(port:port);

installs = 0;
foreach dir( make_list_unique("/basilix", http_cgi_dirs(port:port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = string(dir, "/basilix.php");
  if (port == 443) url = string(url, "?is_ssl=1");

  req = string(
    "GET ",  url, " HTTP/1.1\r\n",
    "Host: ", host, "\r\n",
    "Cookie: BSX_TestCookie=yes\r\n",
    "\r\n"
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (!res)
    continue;

  if ("BasiliX" >< res) {
    # Search for the version string in a couple of different places.
    #
    # - it's usually in the HTML title element.
    title = strstr(res, "<title>");
    if (title != NULL) {
      title = title - strstr(title,string("\n"));
      pat = "BasiliX (.+)</title>";
      ver = eregmatch(pattern:pat, string:title, icase:TRUE);
      if (ver != NULL) ver = ver[1];
    }
    # - otherwise, look at the "generator" meta tag.
    if (isnull(ver)) {
      generator = strstr(res, '<meta name="generator"');
      if (generator != NULL) {
        generator = generator - strstr(generator, string("\n"));
        pat = 'content="BasiliX (.+)"';
        ver = eregmatch(pattern:pat, string:generator, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }
    # - last try, older versions include it in the copyright notice.
    if (isnull(ver)) {
      copyright = strstr(res, "BasiliX v");
      if (copyright != NULL) {
        copyright = copyright - strstr(copyright, string("\n"));
        pat = "BasiliX v(.+) -- &copy";
        ver = eregmatch(pattern:pat, string:copyright, icase:TRUE);
        if (ver != NULL) ver = ver[1];
      }
    }

    set_kb_item(name: "basilix/installed", value: TRUE);

    # Handle reporting
    if (!isnull(ver)) {
      tmp_version = string(ver, " under ", dir);
      set_kb_item(name:string("www/", port, "/basilix"), value:tmp_version);

        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:basilix:basilix_webmail:");
        if (!cpe)
           cpe = 'cpe:/a:basilix:basilix_webmail';

      register_product(cpe: cpe, location: install, port: port, service: "www");

      installations[dir] = ver;
      ++installs;
    }

    if (installs) break;
  }
}


# Report any instances found
if (installs) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("BasiliX ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of BasiliX were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  log_message(port:port, data:info);
  exit(0);
}

exit(0);
