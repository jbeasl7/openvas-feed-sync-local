# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70710");
  script_cve_id("CVE-2009-4214", "CVE-2011-2930", "CVE-2011-2931", "CVE-2011-3186");
  script_tag(name:"creation_date", value:"2012-02-11 08:28:39 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2301");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2301");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rails' package(s) announced via the DSA-2301 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Rails, the Ruby web application framework. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4214

A cross-site scripting (XSS) vulnerability had been found in the strip_tags function. An attacker may inject non-printable characters that certain browsers will then evaluate. This vulnerability only affects the oldstable distribution (lenny).

CVE-2011-2930

A SQL injection vulnerability had been found in the quote_table_name method that could allow malicious users to inject arbitrary SQL into a query.

CVE-2011-2931

A cross-site scripting (XSS) vulnerability had been found in the strip_tags helper. An parsing error can be exploited by an attacker, who can confuse the parser and may inject HTML tags into the output document.

CVE-2011-3186

A newline (CRLF) injection vulnerability had been found in response.rb. This vulnerability allows an attacker to inject arbitrary HTTP headers and conduct HTTP response splitting attacks via the Content-Type header.

For the oldstable distribution (lenny), this problem has been fixed in version 2.1.0-7+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 2.3.5-1.2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 2.3.14.

We recommend that you upgrade your rails packages.

This VT has been deprecated as a duplicate of the VT 'Debian Security Advisory DSA 2301-1 (rails)' (OID: 1.3.6.1.4.1.25623.1.0.70237).");

  script_tag(name:"affected", value:"'rails' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
