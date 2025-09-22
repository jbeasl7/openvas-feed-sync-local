# SPDX-FileCopyrightText: 2011 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70409");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2011-2510");
  script_name("Debian Security Advisory DSA 2320-1 (dokuwiki)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202320-1");
  script_tag(name:"insight", value:"The dokuwiki update included in Debian Lenny 5.0.9 to address a cross
site scripting issue (CVE-2011-2510) had a regression rendering links
to external websites broken. This update corrects that regression.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.0.20080505-4+lenny4.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"We recommend that you upgrade your dokuwiki packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to dokuwiki
announced via advisory DSA 2320-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
