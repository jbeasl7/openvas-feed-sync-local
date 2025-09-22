# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53339");
  script_cve_id("CVE-2003-0138");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-269-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-269-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-269");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'heimdal' package(s) announced via the DSA-269-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-269)' (OID: 1.3.6.1.4.1.25623.1.0.53351).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A cryptographic weakness in version 4 of the Kerberos protocol allows an attacker to use a chosen-plaintext attack to impersonate any principal in a realm. Additional cryptographic weaknesses in the krb4 implementation permit the use of cut-and-paste attacks to fabricate krb4 tickets for unauthorized client principals if triple-DES keys are used to key krb4 services. These attacks can subvert a site's entire Kerberos authentication infrastructure.

This version of the heimdal package changes the default behavior and disallows cross-realm authentication for Kerberos version 4. Because of the fundamental nature of the problem, cross-realm authentication in Kerberos version 4 cannot be made secure and sites should avoid its use. A new option (--kerberos4-cross-realm) is provided to the kdc command to re-enable version 4 cross-realm authentication for those sites that must use this functionality but desire the other security fixes.

For the stable distribution (woody) this problem has been fixed in version 0.4e-7.woody.8.

The old stable distribution (potato) is not affected by this problem, since it isn't compiled against kerberos 4.

For the unstable distribution (sid) this problem has been fixed in version 0.5.2-1.

We recommend that you upgrade your heimdal packages immediately.");

  script_tag(name:"affected", value:"'heimdal' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
