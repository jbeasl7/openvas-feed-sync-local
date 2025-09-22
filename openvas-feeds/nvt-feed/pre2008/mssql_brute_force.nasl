# SPDX-FileCopyrightText: 2005 HD Moore
# SPDX-FileCopyrightText: New / improved code since 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

DEFAULT_ACCOUNT_TEST_THRESHOLD = 2;
CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10862");
  script_version("2024-07-24T05:06:37+0000");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-12 13:55:00 +0000 (Tue, 12 Oct 2021)");
  script_cve_id("CVE-2021-33583", "CVE-2024-6912");
  script_name("Microsoft SQL (MSSQL) Server Brute Force Logins With Default Credentials (TCP/IP Listener)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 HD Moore");
  script_family("Brute force attacks");
  script_dependencies("gb_microsoft_sql_server_tcp_ip_listener_detect.nasl",
                      "gb_default_credentials_options.nasl");
  script_require_ports("Services/mssql", 1433);
  script_mandatory_keys("microsoft/sqlserver/tcp_listener/detected");
  script_exclude_keys("default_credentials/disable_brute_force_checks");

  script_add_preference(name:"Max number of passwords tried for each tested account", type:"entry", value:DEFAULT_ACCOUNT_TEST_THRESHOLD, id:1);

  script_tag(name:"summary", value:"The remote Microsoft SQL (MSSQL) Server has a common / publicly
  known password for one or more accounts.");

  script_tag(name:"vuldetect", value:"Tries to login with a number of known default credentials via
  the Microsoft SQL protocol.

  Note: To avoid account lockouts due to possible existing account lockout policies (which are
  enforced on a per-user basis) this VT will only try 2 passwords for each tested account by
  default. This default can be changed (if required) in the preferences of this VT.");

  script_tag(name:"impact", value:"An attacker can use these accounts to read and/or modify data on
  the Microsoft SQL Server. In addition, the attacker may be able to launch programs on the target
  operating system.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - PerkinElmer Inc BioAssay Enterprise

  - Milestone XProtect Essential

  - Arcserve UDP

  - Lansweeper

  - Microsoft Lync 2010

  - Saleslogix

  - Act!

  - PerkinElmer Inc. BioAssay Enterprise

  - PC America Restaurant Pro Express

  - HP MFP Digital Sending Software

  - My Movies

  - Codepal

  - Ecava IntegraXor

  - DHL EasyShip

  - CVE-2021-33583: REINER timeCard 6.x

  - CVE-2024-6912: PerkinElmer ProcessPlus");

  script_tag(name:"solution", value:"Please set a difficult to guess password for the reported
  account(s).");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_brute_force_checks"))
  exit(0);

# MSSQL Brute Forcer
#
# This script checks a MSSQL Server instance for common username and password combinations. If you
# know of a common/default account that is not listed, please submit it to:
#
# https://forum.greenbone.net/c/vulnerability-tests/7
#
# System accounts with blank passwords are checked for in a separate plugin
# (mssql_blank_password.nasl). This plugin is geared towards accounts created by rushed admins or
# certain software installations.

include("host_details.inc");
include("list_array_func.inc");
include("mssql.inc");

account_test_threshold = int(script_get_preference("Max number of passwords tried for each tested account", id:1));
if(account_test_threshold <= 0)
  account_test_threshold = DEFAULT_ACCOUNT_TEST_THRESHOLD;

# nb:
# - Some account / password pairs taken from (last change 8 years ago):
#   https://github.com/mubix/post-exploitation-wiki/blob/master/windows/mssql.md?plain=1
# - If ever required (e.g. a password including ":") we could also exchange the ":" used below with
#   something like e.g. "#---#". Make sure to update the sep:":" in the split() call below.
# - Order matters, e.g. place the "sa:password" which are more likely to be used more up vs. some
#   exotic software like "My Movies" which are probably rarely used these days more down in the list

creds = make_list(

  # Unknown origin / product (generally standard / default?)
  "sa:sa",

  # From https://hub.docker.com/_/microsoft-mssql-server
  "sa:yourStrong(!)Password",

  # Unknown origin / products (generally standard / defaults?)
  "probe:probe",
  "probe:password",
  "sql:sql",

  # PerkinElmer Inc BioAssay Enterprise
  "ELNAdmin:ELNAdmin",

  # Milestone XProtect Essential
  "msi:keyboa5",

  # Arcserve UDP from https://www.mdsec.co.uk/2023/06/cve-2023-26258-remote-code-execution-in-arcserve-udp-backup/
  "arcserve_udp:@rcserveP@ssw0rd",

  # Old Lansweeper releases mentioned in:
  # https://community.lansweeper.com/t5/lansweeper-maintenance/change-the-lansweeper-database-password/ta-p/64305
  "lansweeperuser:mysecretpassword0*",
  "lansweeperuser:Mysecretpassword0*",

  # Some Atlassian Jira examples found "in the wild" on some forums / config examples
  "jirauser:jirapasswd",
  "jirauser:jirauser",

  # nb: These should be kept at the bottom as we want to test e.g. the above "sa" accounts first
  #
  # Unknown origin / products (generally standard / defaults?)
  "admin:administrator",
  "admin:password",
  "admin:admin",
  "sa:password",
  "sa:administrator",
  "sa:admin",
  "sa:sql",
  "sa:SQL",

  # CVE-2021-33583: REINER timeCard 6.x
  "sa:k+7&DG$pXNTy9h_8",

  # Microsoft Lync 2010
  "sa:mypassword",

  # Saleslogix
  "sa:SLXMaster",
  "sa:SLXMa$t3r",

  # Act!
  "sa:sage",
  "sa:ActbySage1!",

  # PerkinElmer Inc. BioAssay Enterprise
  "sa:CambridgeSoft_SA",

  # PC America Restaurant Pro Express
  "sa:PCAmerica",
  "sa:pcAmer1ca",

  # HP MFP Digital Sending Software
  "sa:Hpdsdb000001",
  "sa:hpdss",

  # My Movies
  "sa:t9AranuHA7",

  # Codepal
  "sa:Cod3p@l",

  # Ecava IntegraXor
  "sa:111",

  # DHL EasyShip
  "sa:DHLadmin@1",

  # Some Jira docker examples
  "sa:Password!_first",

  # PerkinElmer ProcessPlus mentioned in https://cyberdanube.com/en/en-multiple-vulnerabilities-in-perten-processplus/
  "sa:enilno"
);

# nb:
# - This is used to avoid "sa" and "admin" account lockouts by default with too many failed logins
# - The idea is that on each tested credential pairs the number in the array value is increased and
#   then tested later again to see if the configured threshold has been reached
tested_accounts_numbers = make_array();
skipped_accounts_list = make_list();

VULN = FALSE;
failed_socket_open = 0;
report = 'It was possible to login to the remote Microsoft SQL (MSSQL) Server with following known credentials:\n';

if(!port = get_app_port(cpe:CPE, service:"tcp_listener"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

foreach cred(creds) {

  # nb: In this case it doesn't make much sense to continue. We still want to report what has been
  # found so far so break; is used here.
  if(failed_socket_open > 4)
    break;

  if(!soc = open_sock_tcp(port)) {
    failed_socket_open++;
    continue;
  }

  cred_split = split(cred, sep:":", keep:FALSE);
  # nb: Shouldn't happen but we're checking it anyway...
  if(!cred_split || max_index(cred_split) != 2) {
    close(soc);
    continue;
  }

  username = cred_split[0];
  password = cred_split[1];

  if(password == "none") {
    pw_text = "No password";
    password = "";
  } else {
    pw_text = '"' + password + '"';
  }

  # nb: See note above why this is used
  if(!array_key_exist(key:username, array:tested_accounts_numbers, part_match:FALSE, icase:FALSE)) {
    tested_accounts_numbers[username] = 1;
  } else {
    current_tested_accounts_numbers = tested_accounts_numbers[username];
    if(current_tested_accounts_numbers >= account_test_threshold) {
      if(!in_array(search:username, array:skipped_accounts_list, part_match:FALSE, icase:FALSE))
        skipped_accounts_list = make_list(username, skipped_accounts_list);
      has_skipped_account = TRUE;
      close(soc);
      continue;
    } else {
      current_tested_accounts_numbers++;
      tested_accounts_numbers[username] = current_tested_accounts_numbers;
    }
  }

  sql_packet = mssql_make_login_pkt(username:username, password:password);

  send(socket:soc, data:sql_packet);
  # nb: mssql_pkt_lang is a global var passed from mssql.inc
  send(socket:soc, data:mssql_pkt_lang);

  r = mssql_recv(socket:soc);
  close(soc);

  if(strlen(r) > 10 && ord(r[8]) == 0xE3) {
    report += '\nAccount: "' + username + '", Password: ' + pw_text;
    VULN = TRUE;
  }
}

if(has_skipped_account) {
  skipped_report = 'Testing of the following account(s) has been stopped due to reaching the configured threshold of "' + account_test_threshold + '":\n';
  foreach skipped_account(skipped_accounts_list)
    skipped_report += '\n' + skipped_account;
  log_message(port:port, data:skipped_report);
}

if(VULN) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
