# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105882");
  script_cve_id("CVE-2012-5958", "CVE-2012-5959", "CVE-2012-5960",
                "CVE-2012-5961", "CVE-2012-5962", "CVE-2012-5963",
                "CVE-2012-5964", "CVE-2012-5965");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2025-01-17T05:37:18+0000");
  script_name("libupnp Multiple Buffer Overflow Vulnerabilities (TCP)");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2013-02-06 15:35:24 +0100 (Wed, 06 Feb 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2013 Greenbone AG");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57602");

  script_tag(name:"solution", value:"libupnp is prone to multiple buffer-overflow vulnerabilities because
  it fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"summary", value:"Updates are available. Please see the references for more information.

  This VT has been deprecated and merged into the VT 'libupnp Multiple Buffer Overflow Vulnerabilities'
  (OID: 1.3.6.1.4.1.25623.1.0.103658.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the device that uses the affected library. Failed exploit
  attempts will likely crash the application.");

  script_tag(name:"affected", value:"libupnp versions prior to 1.6.18 are affected.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
