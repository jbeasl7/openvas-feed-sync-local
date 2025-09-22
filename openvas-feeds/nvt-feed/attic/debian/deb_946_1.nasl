# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56192");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2005-4158", "CVE-2006-0151");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 946-1 (sudo)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_tag(name:"solution", value:"For the stable distribution (sarge) this problem has been fixed in
version 1.6.8p7-1.3.

For the unstable distribution (sid) this problem has been fixed in
version 1.6.8p12-1.

  We recommend that you upgrade your sudo package.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20946-1");
  script_tag(name:"summary", value:"The remote host is missing an update to sudo announced via advisory DSA 946-1.  It has been discovered that sudo, a privileged program, that provides limited super user privileges to specific users, passes several environment variables to the program that runs with elevated privileges.  In the case of include paths (e.g. for Perl, Python, Ruby or other scripting languages) this can cause arbitrary code to be executed as privileged user if the attacker points to a manipulated version of a system library.  This update alters the former behaviour of sudo and limits the number of supported environment variables to LC_*, LANG, LANGUAGE and TERM. Additional variables are only passed through when set as env_check in /etc/sudoers, which might be required for some scripts to continue to work.  For the old stable distribution (woody) this problem has been fixed in version 1.6.6-1.5.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-946)' (OID: 1.3.6.1.4.1.25623.1.0.56531).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
