# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900106");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142",
                "CVE-2008-3143", "CVE-2008-3144");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_name("Python < 2.5.2 Multiple Vulnerabilities - Linux");

  script_xref(name:"URL", value:"http://bugs.python.org/issue2588");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30491");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2589");
  script_xref(name:"URL", value:"http://bugs.python.org/issue2620");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities.

  This VT has been deprecated and replaced by various Local Security Checks (LSC).");

  script_tag(name:"insight", value:"The flaws exist due to integer overflow in,

  - hashlib module, which can lead to an unreliable cryptographic digest results.

  - the processing of unicode strings.

  - the PyOS_vsnprintf() function on architectures that do not have a vsnprintf() function.

  - the PyOS_vsnprintf() function when passing zero-length strings can lead to memory corruption.");

  script_tag(name:"affected", value:"Python 2.5.2 and prior.");

  script_tag(name:"solution", value:"Fix is available in the SVN repository.");

  script_tag(name:"impact", value:"Successful exploitation could potentially causes attackers to
  execute arbitrary code or create a denial of service condition.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

exit(66);
