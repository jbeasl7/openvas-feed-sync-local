# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:moxa:nport";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103664");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2013-02-19 12:01:48 +0100 (Tue, 19 Feb 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Moxa NPort Unprotected Console (HTTP)");

  # nb: No attacking request (just access a default page) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Default Accounts");

  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login (at least currently)...
  script_dependencies("gb_moxa_nport_consolidation.nasl");
  script_mandatory_keys("moxa/nport/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The remote Moxa NPort Web Console is not protected by a
  password.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"solution", value:"Set a password.");

  exit(0);
}

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, first_cpe_only: TRUE))
  exit(0);

port = infos["port"];

url = "/main.htm";

if (http_vuln_check(port: port, url: url, pattern: "Basic Settings",
                    extra_check: make_list("Model Name", "MAC Address"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
