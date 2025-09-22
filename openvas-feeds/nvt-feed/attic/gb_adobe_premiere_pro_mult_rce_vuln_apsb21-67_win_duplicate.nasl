# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826526");
  script_version("2023-09-20T05:05:13+0000");
  script_cve_id("CVE-2021-46816");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-30 15:30:00 +0000 (Thu, 30 Jun 2022)");
  script_tag(name:"creation_date", value:"2021-11-19 09:11:50 +0530 (Fri, 19 Nov 2021)");
  script_name("Adobe Premiere Pro Code Execution Vulnerability (APSB21-67) - Windows");

  script_tag(name:"summary", value:"Adobe Premiere Pro is prone to a code execution vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Adobe Premiere Pro Multiple Code Execution
  Vulnerabilities (APSB21-67) - Windows' (OID: 1.3.6.1.4.1.25623.1.0.818871).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw is due to an access of memory
  location after end of buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Pro 15.4 and prior.");

  script_tag(name:"solution", value:"Update to version 15.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_pro/apsb21-67.html");

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
