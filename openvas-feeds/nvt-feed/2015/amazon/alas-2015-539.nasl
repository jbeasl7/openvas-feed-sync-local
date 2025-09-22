# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120202");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_tag(name:"creation_date", value:"2015-09-08 11:20:01 +0000 (Tue, 08 Sep 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:52:00 +0000 (Tue, 17 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-539)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-539");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-539.html");
  script_xref(name:"URL", value:"http://chrony.tuxfamily.org/News.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony' package(s) announced via the ALAS-2015-539 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"As reported upstream:

When NTP or cmdmon access was configured (from chrony.conf or via authenticated cmdmon) with a subnet size that is indivisible by 4 and an address that has nonzero bits in the 4-bit subnet remainder (e.g. 192.168.15.0/22 or f000::/3), the new setting was written to an incorrect location, possibly outside the allocated array. An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process. (CVE-2015-1821)

When allocating memory to save unacknowledged replies to authenticated command requests, the last 'next' pointer was not initialized to NULL. When all allocated reply slots were used, the next reply could be written to an invalid memory instead of allocating a new slot for it. An attacker that has the command key and is allowed to access cmdmon (only localhost is allowed by default) could exploit this to crash chronyd or possibly execute arbitrary code with the privileges of the chronyd process. (CVE-2015-1822)

An attacker knowing that NTP hosts A and B are peering with each other (symmetric association) can send a packet with random timestamps to host A with source address of B which will set the NTP state variables on A to the values sent by the attacker. Host A will then send on its next poll to B a packet with originate timestamp that doesn't match the transmit timestamp of B and the packet will be dropped. If the attacker does this periodically for both hosts, they won't be able to synchronize to each other. Authentication using a symmetric key can fully protect against this attack, but in implementations following the NTPv3 (RFC 1305) or NTPv4 (RFC 5905) specification the state variables were updated even when the authentication check failed and the association was not protected. (CVE-2015-1853)");

  script_tag(name:"affected", value:"'chrony' package(s) on Amazon Linux.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~1.31.1~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chrony-debuginfo", rpm:"chrony-debuginfo~1.31.1~1.13.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
