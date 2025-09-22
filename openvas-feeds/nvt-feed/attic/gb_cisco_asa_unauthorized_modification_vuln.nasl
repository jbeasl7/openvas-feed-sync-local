# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805760");
  script_version("2025-01-17T15:39:18+0000");
  script_cve_id("CVE-2015-4458");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco ASA Unauthorized Modification Vulnerability (Cisco-SA-20150714-CVE-2015-4458)");

  script_tag(name:"summary", value:"This VT has been deprecated and replaced by the VT 'Cisco ASA Message
  Authentication Code Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.106026).

  Cisco ASA is prone to an unauthorized modification vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient checking of the MAC on TLS
  packets by the Cavium Networks cryptographic module used by an affected device.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to modify the
  contents of an encrypted TLS packet in transit from an affected device.");

  script_tag(name:"affected", value:"Cisco ASA version 9.1(5.21).");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150714-CVE-2015-4458");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");

  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
