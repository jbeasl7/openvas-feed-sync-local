# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-November/019004.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881541");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2012-11-23 11:39:47 +0530 (Fri, 23 Nov 2012)");
  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209",
                "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829",
                "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839",
                "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 17:31:00 +0000 (Thu, 13 Aug 2020)");
  script_xref(name:"CESA", value:"2012:1483");
  script_name("CentOS Update for thunderbird CESA-2012:1483 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2012-4214,
  CVE-2012-4215, CVE-2012-4216, CVE-2012-5829, CVE-2012-5830, CVE-2012-5833,
  CVE-2012-5835, CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

  A buffer overflow flaw was found in the way Thunderbird handled GIF
  (Graphics Interchange Format) images. Content containing a malicious GIF
  image could cause Thunderbird to crash or, possibly, execute arbitrary code
  with the privileges of the user running Thunderbird. (CVE-2012-4202)

  A flaw was found in the way Thunderbird decoded the HZ-GB-2312 character
  encoding. Malicious content could cause Thunderbird to run JavaScript code
  with the permissions of different content. (CVE-2012-4207)

  A flaw was found in the location object implementation in Thunderbird.
  Malicious content could possibly use this flaw to allow restricted content
  to be loaded by plug-ins. (CVE-2012-4209)

  A flaw was found in the way cross-origin wrappers were implemented.
  Malicious content could use this flaw to perform cross-site scripting
  attacks. (CVE-2012-5841)

  A flaw was found in the evalInSandbox implementation in Thunderbird.
  Malicious content could use this flaw to perform cross-site scripting
  attacks. (CVE-2012-4201)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman, Andrew
  McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Masato Kinugawa, Mariusz
  Mlynski, Bobby Holley, and moz_bug_r_a4 as the original reporters of
  these issues.

  Note: All issues except CVE-2012-4202 cannot be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. They could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.11 ESR, which corrects these issues.
  After installing the update, Thunderbird must be restarted for the changes
  to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~10.0.11~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
