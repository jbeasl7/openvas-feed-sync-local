# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64163");
  script_version("2024-01-23T05:05:19+0000");
  script_tag(name:"last_modification", value:"2024-01-23 05:05:19 +0000 (Tue, 23 Jan 2024)");
  script_tag(name:"creation_date", value:"2009-06-05 18:04:08 +0200 (Fri, 05 Jun 2009)");
  script_cve_id("CVE-2008-5027", "CVE-2008-5302", "CVE-2008-5303", "CVE-2008-2435", "CVE-2008-1102", "CVE-2008-4863", "CVE-2008-5028", "CVE-2007-3555", "CVE-2008-1502", "CVE-2008-3325", "CVE-2008-3326", "CVE-2008-4796", "CVE-2008-4810", "CVE-2008-4811", "CVE-2008-5432", "CVE-2008-5619", "CVE-2008-2426", "CVE-2008-2434", "CVE-2008-4242", "CVE-2007-3372", "CVE-2008-5081", "CVE-2008-4577", "CVE-2008-4870", "CVE-2008-5140", "CVE-2008-5312", "CVE-2008-5313", "CVE-2008-4844", "CVE-2008-2237", "CVE-2008-2238", "CVE-2008-4937");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 02:46:00 +0000 (Sun, 21 Jan 2024)");
  script_name("Ubuntu USN-698-1 (nagios)");
  script_category(ACT_GATHER_INFO);
  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-698-1/");
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Ubuntu Local Security Checks");

  script_tag(name:"insight", value:"It was discovered that Nagios did not properly parse commands submitted using
the web interface. An authenticated user could use a custom form or a browser
addon to bypass security restrictions and submit unauthorized commands.");
  script_tag(name:"summary", value:"The remote host is missing an update to nagios
announced via advisory USN-698-1.");
  script_tag(name:"solution", value:"The problem can be corrected by upgrading your system to the
 following package versions:

Ubuntu 6.06 LTS:
  nagios-common                   2:1.3-cvs.20050402-8ubuntu8

After a standard system upgrade you need to restart Nagios to effect
the necessary changes.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
