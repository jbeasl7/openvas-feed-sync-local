# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805759");
  script_version("2023-10-27T16:11:33+0000");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-10-07 18:52:56 +0530 (Wed, 07 Oct 2015)");

  script_cve_id("CVE-2015-4241");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco ASA DoS Vulnerability (Cisco-SA-20150707-CVE-2015-4241)");

  script_tag(name:"summary", value:"Cisco ASA is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Cisco ASA OSPFv2 DoS Vulnerability' (OID:
  1.3.6.1.4.1.25623.1.0.106027).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to improper handling of OSPFv2 packets by an
  affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service attack.");

  script_tag(name:"affected", value:"Cisco ASA version 9.3.2.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/Cisco-SA-20150707-CVE-2015-4241");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");

  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
