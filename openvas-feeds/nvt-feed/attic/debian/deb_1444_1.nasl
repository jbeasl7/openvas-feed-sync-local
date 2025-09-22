# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60099");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 23:23:47 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2007-3799", "CVE-2007-3998", "CVE-2007-4657", "CVE-2007-4658", "CVE-2007-4659", "CVE-2007-4660", "CVE-2007-4662", "CVE-2007-5898", "CVE-2007-5899");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 1444-1 (php5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201444-1");
  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in PHP, a
server-side, HTML-embedded scripting language. The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2007-3799

It was discovered that the session_start() function allowed the
insertion of attributes into the session cookie.

CVE-2007-3998

Mattias Bengtsson and Philip Olausson discovered that a
programming error in the implementation of the wordwrap() function
allowed denial of service through an infinite loop.

CVE-2007-4658

Stanislav Malyshev discovered that a format string vulnerability
in the money_format() function could allow the execution of
arbitrary code.

CVE-2007-4659

Stefan Esser discovered that execution control flow inside the
zend_alter_ini_entry() function in handled incorrectly in case
of a memory limit violation.

CVE-2007-4660

Gerhard Wagner discovered an integer overflow inside the
chunk_split function().

CVE-2007-5898

Rasmus Lerdorf discovered that incorrect parsing of multibyte
sequences may lead to disclosure of memory contents.

CVE-2007-5899

It was discovered that the output_add_rewrite_var() function could
leak session ID information, resulting in information disclosure.

This update also fixes two bugs from in the PHP 5.2.4 release which
don't have security impact according to the Debian PHP security policy
(CVE-2007-4657 and CVE-2007-4662), but which are fixed nonetheless.


For the stable distribution (etch), these problems have been fixed in
version 5.2.0-8+etch9.

The old stable distribution (sarge) doesn't contain php5.

For the unstable distribution (sid), these problems have been fixed
in version 5.2.4-1, with the exception of CVE-2007-5898 and
CVE-2007-5899, which will be fixed soon. Please note that Debian's
version of PHP is hardened with the Suhosin patch beginning with
version 5.2.4-1, which renders several vulnerabilities ineffective.");

  script_tag(name:"solution", value:"We recommend that you upgrade your php5 packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to php5 announced via advisory DSA 1444-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-1444)' (OID: 1.3.6.1.4.1.25623.1.0.60267).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
