# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871809");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-05-09 06:48:42 +0200 (Tue, 09 May 2017)");
  script_cve_id("CVE-2016-10195", "CVE-2016-10196", "CVE-2016-10197", "CVE-2017-5429",
                "CVE-2017-5432", "CVE-2017-5433", "CVE-2017-5434", "CVE-2017-5435",
                "CVE-2017-5436", "CVE-2017-5438", "CVE-2017-5439", "CVE-2017-5440",
                "CVE-2017-5441", "CVE-2017-5442", "CVE-2017-5443", "CVE-2017-5444",
                "CVE-2017-5445", "CVE-2017-5446", "CVE-2017-5447", "CVE-2017-5449",
                "CVE-2017-5451", "CVE-2017-5454", "CVE-2017-5459", "CVE-2017-5460",
                "CVE-2017-5464", "CVE-2017-5465", "CVE-2017-5466", "CVE-2017-5467",
                "CVE-2017-5469");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-07 18:44:00 +0000 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for thunderbird RHSA-2017:1201-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail
and newsgroup client.

This update upgrades Thunderbird to version 52.1.0.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2017-5429, CVE-2017-5433, CVE-2017-5435, CVE-2017-5436,
CVE-2017-5459, CVE-2017-5466, CVE-2017-5432, CVE-2017-5434, CVE-2017-5438,
CVE-2017-5439, CVE-2017-5440, CVE-2017-5441, CVE-2017-5442, CVE-2017-5443,
CVE-2017-5444, CVE-2017-5446, CVE-2017-5447, CVE-2017-5454, CVE-2017-5460,
CVE-2017-5464, CVE-2017-5465, CVE-2017-5469, CVE-2016-10195,
CVE-2016-10196, CVE-2017-5445, CVE-2017-5449, CVE-2017-5451, CVE-2017-5467,
CVE-2016-10197)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Petr Cerny, Nils, Ivan Fratric (Google Project Zero),
Takeshi Terada, Heather Miller (Google Skia team), Chun Han Hsiao, Chamal
De Silva, Nicolas Gregoire, Holger Fuhrmannek, Atte Kettunen, Haik
Aftandilian, and Jordi Chancel as the original reporters.");
  script_tag(name:"affected", value:"thunderbird on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2017:1201-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-May/msg00001.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~52.1.0~1.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"thunderbird-debuginfo", rpm:"thunderbird-debuginfo~52.1.0~1.el6_9", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
