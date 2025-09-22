# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53190");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2004-0426");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Debian Security Advisory DSA 499-1 (rsync)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20499-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10247");
  script_tag(name:"insight", value:"A vulnerability was discovered in rsync, a file transfer program,
whereby a remote user could cause an rsync daemon to write files
outside of the intended directory tree.  This vulnerability is not
exploitable when the daemon is configured with the 'chroot' option.

For the current stable distribution (woody) this problem has been
fixed in version 2.5.5-0.4.

For the unstable distribution (sid), this problem has been fixed in
version 2.6.1-1.

We recommend that you update your rsync package.");
  script_tag(name:"summary", value:"The remote host is missing an update to rsync announced via advisory DSA 499-1.

  This VT has been deprecated and merged into the VT 'Debian: Security Advisory (DSA-499)' (OID: 1.3.6.1.4.1.25623.1.0.53203).");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
