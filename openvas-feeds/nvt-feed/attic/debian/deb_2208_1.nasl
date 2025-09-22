# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69418");
  script_cve_id("CVE-2011-0414");
  script_tag(name:"creation_date", value:"2011-05-12 17:21:50 +0000 (Thu, 12 May 2011)");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2208-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2208-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2208");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DSA-2208-1 advisory.

  This VT has been deprecated and merged into the VT 'deb_2208.nasl' (OID: 1.3.6.1.4.1.25623.1.0.69418).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BIND, a DNS server, contains a race condition when processing zones updates in an authoritative server, either through dynamic DNS updates or incremental zone transfer (IXFR). Such an update while processing a query could result in deadlock and denial of service. (CVE-2011-0414)

In addition, this security update addresses a defect related to the processing of new DNSSEC DS records by the caching resolver, which may lead to name resolution failures in the delegated zone. If DNSSEC validation is enabled, this issue can make domains ending in .COM unavailable when the DS record for .COM is added to the DNS root zone on March 31st, 2011. An unpatched server which is affected by this issue can be restarted, thus re-enabling resolution of .COM domains. This workaround applies to the version in oldstable, too.

Configurations not using DNSSEC validations are not affected by this second issue.

For the oldstable distribution (lenny), the DS record issue has been fixed in version 1:9.6.ESV.R4+dfsg-0+lenny1. (CVE-2011-0414 does not affect the lenny version.)

For the stable distribution (squeeze), this problem has been fixed in version 1:9.7.3.dfsg-1~squeeze1.

For the testing distribution (wheezy) and the unstable distribution (sid), this problem has been fixed in version 1:9.7.3.dfsg-1.

We recommend that you upgrade your bind9 packages.");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
