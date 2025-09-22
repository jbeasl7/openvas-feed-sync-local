# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108586");
  script_version("2024-12-17T05:05:41+0000");
  # nb:
  # - Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #   avoid too large diffs when adding a new CVE.
  # - The 1999 CVEs are a few generic ones for e.g. Unix accounts or accounts on network devices
  #   having e.g. guessable (a blank password is also guessable), blank or similar passwords.
  # - A few CVEs like e.g. CVE-2018-12072 are Telnet specific and hasn't been added to the related
  #   SSH VT / counterpart
  script_cve_id("CVE-1999-0501",
                "CVE-1999-0502",
                "CVE-1999-0507",
                "CVE-1999-0508",
                "CVE-2018-12072",
                "CVE-2019-5021",
                "CVE-2020-29389",
                "CVE-2020-29564",
                "CVE-2020-29575",
                "CVE-2020-29576",
                "CVE-2020-29577",
                "CVE-2020-29578",
                "CVE-2020-29579",
                "CVE-2020-29580",
                "CVE-2020-29581",
                "CVE-2020-29589",
                "CVE-2020-29591",
                "CVE-2020-29601",
                "CVE-2020-29602",
                "CVE-2020-35184",
                "CVE-2020-35185",
                "CVE-2020-35186",
                "CVE-2020-35187",
                "CVE-2020-35188",
                "CVE-2020-35189",
                "CVE-2020-35190",
                "CVE-2020-35191",
                "CVE-2020-35192",
                "CVE-2020-35193",
                "CVE-2020-35194",
                "CVE-2020-35195",
                "CVE-2020-35196",
                "CVE-2020-35197",
                "CVE-2020-35462",
                "CVE-2020-35463",
                "CVE-2020-35464",
                "CVE-2020-35465",
                "CVE-2020-35466",
                "CVE-2020-35467",
                "CVE-2020-35468",
                "CVE-2020-35469",
                "CVE-2020-6852",
                "CVE-2023-22906"
               );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-03 22:59:00 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2019-05-24 12:35:09 +0000 (Fri, 24 May 2019)");
  script_name("Unpassworded (Blank Password) 'root' Account (Telnet)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "os_detection.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("telnet/banner/available");
  script_exclude_keys("telnet/no_login_banner",
                      "default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://talosintelligence.com/vulnerability_reports/TALOS-2019-0782");
  script_xref(name:"URL", value:"https://alpinelinux.org/posts/Docker-image-vulnerability-CVE-2019-5021.html");
  script_xref(name:"URL", value:"https://github.com/koharin/CVE");

  script_tag(name:"summary", value:"The remote host has set no password for the 'root' account.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with a 'root' username and without a password via
  Telnet.");

  script_tag(name:"insight", value:"It was possible to login via Telnet with the 'root' username and
  without passing a password.");

  script_tag(name:"affected", value:"The following official docker images are known to be affected:

  - Alpine Linux since version 3.3

  - haproxy before version 1.8.18-alpine

  - rabbitmq before version 3.7.13-beta.1-management-alpine

  - memcached before version 1.5.11-alpine

  - influxdb before version 1.7.3-meta-alpine

  - vault before version 0.11.6

  - drupal before version 8.5.10-fpm-alpine

  - plone before version of 4.3.18-alpine

  - kong before version 1.0.2-alpine

  - chronograf before version 1.7.7-alpine

  - telegraf before version 1.9.4-alpine

  - ghost before version 2.16.1-alpine

  - adminer before version 4.7.0-fastcgi

  - composer before version 1.8.3

  - sonarqube

  - irssi before version 1.1-alpine

  - notary before version signer-0.6.1-1

  - spiped before version 1.5-alpine

  - Express Gateway before version 1.14.0

  - storm before version 1.2.1

  - piwik

  - znc before version 1.7.1-slim

  - elixir before version 1.8.0-alpine

  - eggdrop before version 1.8.4rc2

  - Consul versions 0.7.1 through 1.4.2

  - Crux Linux versions 3.0 through 3.4

  - Software AG Terracotta Server OSS version 5.4.1

  - Appbase streams version 2.1.2

  - Docker Docs versions through 2020-12-14

  - Blackfire versions through 2020-12-14

  - FullArmor HAPI File Share Mount versions through 2020-12-14

  - Weave Cloud Agent version 1.3.0

  - Instana Dynamic APM version 1.0.0

  - CoScale agent version 3.16.0

  - registry versions through 2.7.0

  - kapacitor versions through 1.5.0-alpine

  In addition the following devices are / software is known to be affected as well:

  - CVE-2018-12072: Cloud Media Popcorn A-200 03-05-130708-21-POP-411-000

  - CVE-2020-6852: CACAGOO Cloud Storage Intelligent Camera TV-288ZD-2MP with firmware 3.4.2.0919

  - CVE-2023-22906: Hero Qubo HCD01_02_V1.38_20220125 devices

  Other products / devices / images might be affected as well.");

  script_tag(name:"solution", value:"- Set a password for the 'root' account

  - For the Alpine Linux Docker image update to one of the following image releases:

  edge (20190228 snapshot), v3.9.2, v3.8.4, v3.7.3, v3.6.5

  - For other products / devices / images either see the 'affected' tag for fixed releases or
  contact the vendor for more information");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("default_account.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = telnet_get_port( default:23 );
if( get_kb_item( "telnet/" + port + "/no_login_banner" ) )
  exit( 0 );

if( _check_telnet( port:port, login:"root" ) ) {
  report = "It was possible to login as user 'root' without a password and to execute the 'id' command.";
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
