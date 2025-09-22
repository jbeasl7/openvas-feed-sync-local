# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58584");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-2438", "CVE-2007-2953");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 1364-1 (vim)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201364-1");
  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the vim editor. The Common
Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2953

Ulf Harnhammar discovered that a format string flaw in helptags_one() from
src/ex_cmds.c (triggered through the helptags command) can lead to the
execution of arbitrary code.

CVE-2007-2438

Editors often provide a way to embed editor configuration commands (aka
modelines) which are executed once a file is opened. Harmful commands
are filtered by a sandbox mechanism. It was discovered that function
calls to writefile(), feedkeys() and system() were not filtered, allowing
shell command execution with a carefully crafted file opened in vim.

For the oldstable distribution (sarge) these problems have been fixed in
version 6.3-071+1sarge2. Sarge is not affected by CVE-2007-2438.

For the stable distribution (etch) these problems have been fixed
in version 7.0-122+1etch3.

For the unstable distribution (sid) these problems have been fixed in
version 7.1-056+1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your vim packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to vim announced via advisory DSA 1364-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1364)' (OID: 1.3.6.1.4.1.25623.1.0.58613).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
