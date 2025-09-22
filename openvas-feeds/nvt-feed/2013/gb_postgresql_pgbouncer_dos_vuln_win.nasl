# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903102");
  script_version("2025-09-01T05:39:44+0000");
  script_cve_id("CVE-2012-4575");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-01 05:39:44 +0000 (Mon, 01 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-01-25 11:24:17 +0530 (Fri, 25 Jan 2013)");
  script_name("PostgreSQL PgBouncer Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56371");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79751");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/11/02/8");
  script_xref(name:"URL", value:"http://git.postgresql.org/gitweb/?p=pgbouncer.git;a=commit;h=4b92112b820830b30cd7bc91bef3dd8f35305525");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_postgresql_consolidation.nasl");
  script_mandatory_keys("postgresql/smb-login/detected");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application
  to crash by creating a denial of service condition.");

  script_tag(name:"affected", value:"PostgreSQL PgBouncer Pooler version 1.5.2 and prior on Windows.");

  script_tag(name:"insight", value:"An error exists within the 'add_database' function in objects.c in the
  pgbouncer pooler when adding new databases with an overly large name.");

  script_tag(name:"solution", value:"Upgrade to PostgreSQL PgBouncer Pooler version 1.5.3 or later.");

  script_tag(name:"summary", value:"PostgreSQL PgBouncer pooler is prone to a denial of service vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!get_app_version(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

key = "SOFTWARE\EnterpriseDB\PgBouncer";
if(!registry_key_exists(key:key))
  exit(0);

if(!vers = registry_get_sz(key:key, item:"Version"))
  exit(0);

if("-" >< vers)
  vers = str_replace(pattern:"-", string:vers, replace:".");

if(version_is_less(version:vers, test_version:"1.5.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.5.3", reg_checked:key + "!Version");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
