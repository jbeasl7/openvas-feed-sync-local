# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64754");
  script_cve_id("CVE-2008-1502", "CVE-2008-4106", "CVE-2008-4769", "CVE-2008-4796", "CVE-2008-5113", "CVE-2008-6762", "CVE-2008-6767", "CVE-2009-2334", "CVE-2009-2851", "CVE-2009-2853", "CVE-2009-2854");
  script_tag(name:"creation_date", value:"2009-09-02 02:58:39 +0000 (Wed, 02 Sep 2009)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1871-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1871-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1871");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wordpress' package(s) announced via the DSA-1871-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_1871.nasl' (OID: 1.3.6.1.4.1.25623.1.0.64754).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in wordpress, weblog manager. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-6762

It was discovered that wordpress is prone to an open redirect vulnerability which allows remote attackers to conduct phishing atacks.

CVE-2008-6767

It was discovered that remote attackers had the ability to trigger an application upgrade, which could lead to a denial of service attack.

CVE-2009-2334

It was discovered that wordpress lacks authentication checks in the plugin configuration, which might leak sensitive information.

CVE-2009-2854

It was discovered that wordpress lacks authentication checks in various actions, thus allowing remote attackers to produce unauthorised edits or additions.

CVE-2009-2851

It was discovered that the administrator interface is prone to a cross-site scripting attack.

CVE-2009-2853

It was discovered that remote attackers can gain privileges via certain direct requests.

CVE-2008-1502

It was discovered that the _bad_protocol_once function in KSES, as used by wordpress, allows remote attackers to perform cross-site scripting attacks.

CVE-2008-4106

It was discovered that wordpress lacks certain checks around user information, which could be used by attackers to change the password of a user.

CVE-2008-4769

It was discovered that the get_category_template function is prone to a directory traversal vulnerability, which could lead to the execution of arbitrary code.

CVE-2008-4796

It was discovered that the _httpsrequest function in the embedded snoopy version is prone to the execution of arbitrary commands via shell metacharacters in https URLs.

CVE-2008-5113

It was discovered that wordpress relies on the REQUEST superglobal array in certain dangerous situations, which makes it easier to perform attacks via crafted cookies.

For the oldstable distribution (etch), these problems have been fixed in version 2.0.10-1etch4.

For the stable distribution (lenny), these problems have been fixed in version 2.5.1-11+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 2.8.3-1.

We recommend that you upgrade your wordpress packages.");

  script_tag(name:"affected", value:"'wordpress' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
