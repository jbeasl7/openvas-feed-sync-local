# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ge:ups_snmp_web_adapter_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807075");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-0861", "CVE-2016-0862");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-10 01:29:00 +0000 (Sun, 10 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:29 +0530 (Tue, 01 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("GE SNMP/Web Interface Multiple Vulnerabilities");

  script_tag(name:"summary", value:"SNMP/Web Interface adapter is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Device does not perform strict input validation.

  - File contains sensitive account information stored in cleartext.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated users to execute arbitrary command on the system and to obtain
  sensitive cleartext account information impacting the confidentiality,
  integrity, and availability of the system.");

  script_tag(name:"affected", value:"General Electric (GE) Industrial Solutions
  UPS SNMP/Web Adapter devices with firmware version before 4.8");

  script_tag(name:"solution", value:"Upgrade to GE SNMP/Web Interface adapter
  version 4.8 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82407");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-033-02");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ge_snmp_web_interface_adapter_detect.nasl");
  script_mandatory_keys("SNMP/Web/Adapter/Installed");
  script_xref(name:"URL", value:"http://www.geindustrial.com");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!gePort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!geVer = get_app_version(cpe:CPE, port:gePort)){
  exit(0);
}

if(version_is_less(version:geVer, test_version:"4.8"))
{
  report = report_fixed_ver(installed_version:geVer, fixed_version:"4.8");
  security_message(port:gePort, data:report);
  exit(0);
}
