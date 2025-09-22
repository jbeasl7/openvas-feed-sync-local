# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107162");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2017-05-02 11:40:28 +0200 (Tue, 02 May 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 16:15:00 +0000 (Mon, 17 Feb 2020)");

  script_cve_id("CVE-2017-7216");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Palo Alto PAN-OS Information Disclosure Vulnerability (PAN-SA-2017-0010)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Palo Alto PAN-OS Local Security Checks");

  script_tag(name:"summary", value:"Palo Alto PAN-OS is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Management Web Interface does not properly validate specific
  request parameters which can potentially allow for information disclosure.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information
  that may aid in launching further attacks.");

  script_tag(name:"affected", value:"Palo Alto PAN-OS version 7.1.8 and prior.");

  script_tag(name:"solution", value:"Update to version 7.1.9 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97590");
  script_xref(name:"URL", value:"https://security.paloaltonetworks.com/CVE-2017-7216");

  # Already covered in 2017/gb_panos_pan_sa-2017_0010.nasl
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
