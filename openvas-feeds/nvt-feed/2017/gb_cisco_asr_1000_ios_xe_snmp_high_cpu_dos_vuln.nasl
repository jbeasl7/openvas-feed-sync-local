# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809799");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-3820");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-07 17:06:10 +0530 (Tue, 07 Feb 2017)");
  script_name("Cisco ASR 1000 Series Aggregation Services Routers IOS XE SNMP DoS Vulnerability");

  script_tag(name:"summary", value:"Cisco ASR 1000 Series Aggregation Services router with Cisco IOS XE Software is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect initialized
  variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to increase CPU usage to 99% on an affected device and cause a DoS
  condition.");

  script_tag(name:"affected", value:"Cisco ASR 1000 Series Aggregation Services
  Routers that are running Cisco IOS XE Software Release 3.13.6S, 3.16.2S, or
  3.17.1S are affected.");

  script_tag(name:"solution", value:"Upgrade to latest release of Cisco ASR 1000
  Series Aggregation Services router or Cisco IOS XE Software.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux68796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95934");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170201-asrsnmp");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_dependencies("gb_cisco_ios_xe_consolidation.nasl");
  script_mandatory_keys("cisco/ios_xe/detected", "cisco/ios_xe/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ciscoVersion = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if(!model = get_kb_item("cisco/ios_xe/model"))
  exit(0);

if(model !~ '^ASR1')
  exit(0);

affected = make_list('3.13.6S', '3.16.2S', '3.17.1S');

foreach version (affected)
{
  if( ciscoVersion == version)
  {
    report = report_fixed_ver( installed_version:ciscoVersion, fixed_version:"See advisory" );
    security_message( port:0, data:report);
    exit(0);
  }
}

exit(99);
