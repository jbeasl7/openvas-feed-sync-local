# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.52171");
  script_version("2024-02-02T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
  script_cve_id("CVE-2005-0490");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 03:05:29 +0000 (Fri, 02 Feb 2024)");
  script_name("FreeBSD Ports: curl");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following package is affected: curl

CVE-2005-0490
Multiple stack-based buffer overflows in libcURL and cURL 7.12.1, and
possibly other versions, allow remote malicious web servers to execute
arbitrary code via base64 encoded replies that exceed the intended
buffer lengths when decoded, which is not properly handled by (1) the
Curl_input_ntlm function in http_ntlm.c during NTLM authentication or
(2) the Curl_krb_kauth and krb4_auth functions in krb4.c during
Kerberos authentication.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110902850731457");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12615");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12616");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=110902601221592");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/96df5fd0-8900-11d9-aa18-0001020eed82.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"curl");
if(!isnull(bver) && revcomp(a:bver, b:"7.13.1")<0) {
  txt += 'Package curl version ' + bver + ' is installed which is known to be vulnerable.\n';
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}