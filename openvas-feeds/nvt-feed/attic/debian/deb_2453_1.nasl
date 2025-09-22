# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71257");
  script_cve_id("CVE-2012-2085", "CVE-2012-2086", "CVE-2012-2093");
  script_tag(name:"creation_date", value:"2012-04-30 11:57:35 +0000 (Mon, 30 Apr 2012)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2453-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2453-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2453");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gajim' package(s) announced via the DSA-2453-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-2453)' (OID: 1.3.6.1.4.1.25623.1.0.71258).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Gajim, a feature-rich Jabber client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2012-1987

Gajim is not properly sanitizing input before passing it to shell commands. An attacker can use this flaw to execute arbitrary code on behalf of the victim if the user e.g. clicks on a specially crafted URL in an instant message.

CVE-2012-2093

Gajim is using predictable temporary files in an insecure manner when converting instant messages containing LaTeX to images. A local attacker can use this flaw to conduct symlink attacks and overwrite files the victim has write access to.

CVE-2012-2086

Gajim is not properly sanitizing input when logging conversations which results in the possibility to conduct SQL injection attacks.

For the stable distribution (squeeze), this problem has been fixed in version 0.13.4-3+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 0.15-1.

For the unstable distribution (sid), this problem has been fixed in version 0.15-1.

We recommend that you upgrade your gajim packages.");

  script_tag(name:"affected", value:"'gajim' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
