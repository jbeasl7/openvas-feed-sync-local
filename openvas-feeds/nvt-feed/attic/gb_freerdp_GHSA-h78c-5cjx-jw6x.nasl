# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124684");
  script_version("2026-06-17T07:24:12+0000");
  script_tag(name:"last_modification", value:"2026-06-17 07:24:12 +0000 (Wed, 17 Jun 2026)");
  script_tag(name:"creation_date", value:"2026-01-08 07:00:11 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-02 16:41:23 +0000 (Fri, 02 Jan 2026)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2025-68118");

  script_name("FreeRDP Heap Buffer Overflow Vulnerability (GHSA-h78c-5cjx-jw6x)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Buffer overflow");

  script_tag(name:"summary", value:"FreeRDP is prone to a heap buffer overflow vulnerability.

  This VT has been deprecated since the detection only supports Linux, yet the vulnerability
  affects only Windows installations.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability exists in FreeRDP's certificate handling code
  on Windows platforms. The function `freerdp_certificate_data_hash_` uses the Microsoft-specific
  `_snprintf` function to format certificate cache filenames without guaranteeing NUL termination
  when truncation occurs.");

  script_tag(name:"impact", value:"In default configurations, the connection is typically
  terminated before sensitive data can be meaningfully exposed, but unintended memory read or a
  client crash may still occur under certain conditions.");

  script_tag(name:"affected", value:"FreeRDP prior to version 3.20.0.");

  script_tag(name:"solution", value:"Update to version 3.20.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-h78c-5cjx-jw6x");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/pull/12072");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
