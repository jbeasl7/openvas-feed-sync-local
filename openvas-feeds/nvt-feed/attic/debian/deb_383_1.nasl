# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53667");
  script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-383-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-383-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/dsa-383");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ssh-krb5' package(s) announced via the DSA-383-1 advisory.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-383)' (OID: 1.3.6.1.4.1.25623.1.0.53700).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several bugs have been found in OpenSSH's buffer handling. It is not known if these bugs are exploitable, but as a precaution an upgrade is advised.

DSA-383-2: This advisory is an addition to the earlier DSA-383-1 advisory: Solar Designer found four more bugs in OpenSSH that may be exploitable.

For the Debian stable distribution these bugs have been fixed in version 1:3.4p1-0woody4.

We recommend that you update your ssh-krb5 package.");

  script_tag(name:"affected", value:"'ssh-krb5' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
