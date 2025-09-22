# SPDX-FileCopyrightText: 2001 Intranode <plugin@intranode.com>
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Should also cover BID:4135/CVE-2002-0056

CPE = "cpe:/a:microsoft:sql_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10642");
  script_version("2024-06-21T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-0642");
  script_xref(name:"IAVA", value:"2002-B-0004");
  script_name("Microsoft SQL Server SQL Abuse Vulnerability (Q256052)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 Intranode <plugin@intranode.com>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sql_server_consolidation.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sqlserver/smb-login/detected");

  script_xref(name:"URL", value:"https://web.archive.org/web/20040703090735/http://support.microsoft.com/default.aspx?scid=kb;en-us;256052");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210221034811/http://www.securityfocus.com/bid/5205");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210221034811/http://online.securityfocus.com/archive/1/285915");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210221034811/http://online.securityfocus.com/advisories/4308");

  script_tag(name:"summary", value:"The remote SQL server seems to be vulnerable to the SQL abuse
  vulnerability described in technet article Q256052.");

  script_tag(name:"impact", value:"This problem allows an attacker who has to ability to execute SQL
  queries on this host to gain elevated privileges.");

  script_tag(name:"solution", value:"The vendor has releases updates, please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");

function check_key(key) {
  item = "AllowInProcess";
  value = registry_get_dword(key:key, item:item);
  if(!isnull(value) && strlen(value) == 4) {
    item = "DisallowAdHocAccess";
    value = registry_get_dword(key:key, item:item);
    if((strlen(value)) == 0) {
      return(1);
    }
    else if(ord(value[0]) == 0)
      return(1);
  }
  return(0);
}

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

if(!vers = infos["internal_version"])
  exit(0);

# nb: 2000 (8.x) and earlier should be only affected
if(vers !~ "^[1-8]\.")
  exit(99);

location = infos["location"];

key = "SOFTWARE\Microsoft\MSSQLServer\Providers\MSDAORA";
check = check_key(key:key);
if(check) {
  report = report_fixed_ver(installed_version:vers, reg_checked:key, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

key = "SOFTWARE\Microsoft\MSSQLServer\Providers\MSDASQL";
check = check_key(key:key);
if(check) {
  report = report_fixed_ver(installed_version:vers, reg_checked:key, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

key = "SOFTWARE\Microsoft\MSSQLServerProviders\SQLOLEDB";
check = check_key(key:key);
if(check) {
  report = report_fixed_ver(installed_version:vers, reg_checked:key, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

key = "SOFTWARE\Microsoft\MSSQLServerProviders\Microsoft.Jet.OLEDB.4.0";
check = check_key(key:key);
if(check) {
  report = report_fixed_ver(installed_version:vers, reg_checked:key, fixed_version:"See references", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
