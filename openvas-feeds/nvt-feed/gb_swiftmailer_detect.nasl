# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809772");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-12-29 17:59:59 +0530 (Thu, 29 Dec 2016)");
  script_name("SwiftMailer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of SwiftMailer Library.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

phpPort = http_get_port(default:80);
if(!http_can_host_php(port:phpPort)) exit(0);

foreach dir(make_list_unique("/", "/swiftmailer", "/SwiftMailer", http_cgi_dirs(port:phpPort)))
{
  install = dir;
  if(dir == "/") dir = "";

  foreach path (make_list("", "/lib"))
  {
    foreach file (make_list("/composer.json", "/README", "/CHANGES", "/"))
    {
      res = http_get_cache(item: dir + path + file, port:phpPort);

      if((res =~ "^HTTP/1\.[01] 200") &&
         ('swiftmailer"' >< res && '"MIT"' >< res && 'swiftmailer.org"' >< res) ||
         ("Swift Mailer, by Chris Corbyn" >< res && "swiftmailer.org" >< res)||
         ("Swift_Mailer::batchSend" >< res && "Swiftmailer" >< res))
      {
        foreach verfile (make_list("/VERSION", "/version"))
        {
          res1 = http_get_cache(item: dir + path + verfile, port:phpPort);

          if(res1 =~ "^HTTP/1\.[01] 200")
          {
            version = eregmatch(pattern:'Swift-([0-9.]+)([A-Za-z0-9]-)?', string: res1);
            if(version[1])
            {
              version = version[1];
              version = ereg_replace(pattern:"-", string:version, replace:".");

              set_kb_item(name:"www/" + phpPort + "/swiftmailer", value:version);
              set_kb_item(name:"swiftmailer/Installed", value:TRUE);

              # CPE not registered yet
              cpe = build_cpe( value:version, exp:"([0-9A-Za-z.]+)", base:"cpe:/a:swiftmailer:swiftmailer:");
              if( isnull(cpe ))
                cpe = 'cpe:/a:swiftmailer:swiftmailer';

              register_product(cpe:cpe, location:install, port:phpPort, service:"www");

              log_message(data:build_detection_report(app:"SwiftMailer",
                                                      version:version,
                                                      install:install,
                                                      cpe:cpe,
                                                      concluded:version),
                                                      port:phpPort);
              exit(0);
            }
          }
        }
      }
    }
  }
}
exit(0);
