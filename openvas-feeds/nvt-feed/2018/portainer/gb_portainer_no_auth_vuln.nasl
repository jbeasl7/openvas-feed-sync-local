# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:portainer:portainer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114017");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2018-08-06 13:40:12 +0200 (Mon, 06 Aug 2018)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Portainer UI No Authentication Vulnerability (HTTP)");

  # nb: No attacking request (just access a default page) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_portainer_http_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("portainer/detected", "keys/is_public_addr");
  script_require_ports("Services/www", 9000);

  script_tag(name:"summary", value:"The script checks if the Portainer Dashboard UI has no
  authentication enabled at the remote web server.");

  script_tag(name:"vuldetect", value:"Checks if authentication is enabled.

  Note:

  This VT is only reporting a vulnerability if the target system / service is accessible from a
  public WAN (Internet) / public LAN.

  A configuration option 'Network type' to define if a scanned network should be seen as a public
  LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"The installation of Portainer might be misconfigured and
  therefore unprotected and exposed to the public.");

  script_tag(name:"impact", value:"Access to the dashboard gives you top level access to all aspects
  of administration for the cluster it is assigned to manage. That includes managing applications,
  containers, starting workloads, adding and modifying applications, and setting key security
  controls.");

  script_tag(name:"solution", value:"It is highly recommended to enable authentication and create an
  administrator user to avoid exposing your dashboard with administrator privileges to the public.
  Always choose a secure password, especially if your dashboard is exposed to the public.");

  script_xref(name:"URL", value:"https://info.lacework.com/hubfs/Containers%20At-Risk_%20A%20Review%20of%2021%2C000%20Cloud%20Environments.pdf");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("network_func.inc");

# nb: This might be acceptable from user side if the system is located within a restricted LAN so
# allow this case via the configuration within global_settings.nasl.
if(!is_public_addr())
  exit(0);

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

res = http_get_cache(port: port, item: "/api/status");
if(!res)
  exit(0);

if(egrep(pattern: '\\"Authentication\\"\\s*:\\s*false', string: res)) {
  report = "Authentication in Portainer Dashboard UI is disabled!";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
