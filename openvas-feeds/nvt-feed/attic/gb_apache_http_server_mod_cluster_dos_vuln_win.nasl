# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812579");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2016-8612");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-03-21 11:34:53 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache HTTP Server 'mod_cluster' Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in protocol
  parsing logic of mod_cluster load balancer Apache HTTP Server modules that
  allows attacker to cause a Segmentation Fault in the serving httpd process.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service condition.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.23.");

  script_tag(name:"solution", value:"See the vendor advisory for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1387605");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94939");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=57169");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web Servers");

  # This is a Redhat vulnerability (mod_cluster) and not in Apache itself
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);