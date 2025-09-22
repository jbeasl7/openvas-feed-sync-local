# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:asr_1000";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809795");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-3820");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-02-06 17:06:10 +0530 (Mon, 06 Feb 2017)");
  script_name("Cisco ASR 1000 Series Aggregation Services Routers SNMP High CPU DoS Vulnerability");

  script_tag(name:"summary", value:"Cisco ASR 1000 Series Aggregation Services router is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect initialized
  variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to increase CPU usage to 99% on an affected device and cause a DoS
  condition.");

  script_tag(name:"affected", value:"Cisco ASR 1000 Series Aggregation Services Routers with versions 15.5(3)S2.1,
  15.6(1)S1.1, 15.4(3)S6, 15.5(3)S2, 15.6(1)S1.");

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
  script_dependencies("gb_cisco_asr_1000_detect.nasl");
  script_mandatory_keys("cisco_asr_1000/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ciscoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!ciscoVers = get_app_version(cpe:CPE, port:ciscoPort)){
  exit(0);
}

if((ciscoVers == "15.5(3)S2.1")||
   (ciscoVers == "15.6(1)S1.1")||
   (ciscoVers == "15.4(3)S6") ||
   (ciscoVers == "15.5(3)S2") ||
   (ciscoVers == "15.6(1)S1"))
{
  report = report_fixed_ver(  installed_version:ciscoVers, fixed_version: "See vendor advisory" );
  security_message( port:ciscoPort, data:report);
  exit(0);
}
