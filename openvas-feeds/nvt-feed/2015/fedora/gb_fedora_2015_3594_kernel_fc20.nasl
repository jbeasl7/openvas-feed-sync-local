# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869091");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-03-15 06:39:41 +0100 (Sun, 15 Mar 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1421", "CVE-2015-0275", "CVE-2015-1593", "CVE-2014-8160",
                "CVE-2014-9585", "CVE-2014-9529", "CVE-2014-9419", "CVE-2014-9428",
                "CVE-2014-8989", "CVE-2014-8559", "CVE-2014-8133", "CVE-2014-8134",
                "CVE-2014-9090", "CVE-2014-7843", "CVE-2014-7842", "CVE-2014-7841",
                "CVE-2014-7826", "CVE-2014-7825", "CVE-2014-3610", "CVE-2014-3611",
                "CVE-2014-3646", "CVE-2014-8369", "CVE-2014-3688", "CVE-2014-3687",
                "CVE-2014-3673", "CVE-2014-3690", "CVE-2014-8086", "CVE-2014-7975",
                "CVE-2014-7970", "CVE-2014-6410", "CVE-2014-3186", "CVE-2014-3181",
                "CVE-2014-3631", "CVE-2014-5077", "CVE-2014-4171", "CVE-2014-5045",
                "CVE-2014-3534", "CVE-2014-4943", "CVE-2014-4715", "CVE-2014-4699",
                "CVE-2014-0206", "CVE-2014-4508", "CVE-2014-4014", "CVE-2014-3153",
                "CVE-2014-3940", "CVE-2014-3917", "CVE-2014-3144", "CVE-2014-3145",
                "CVE-2014-1738", "CVE-2014-1737", "CVE-2014-0181", "CVE-2014-0196",
                "CVE-2014-3122", "CVE-2014-2851", "CVE-2014-0155", "CVE-2014-2678",
                "CVE-2014-2580", "CVE-2014-0077", "CVE-2014-0055", "CVE-2014-2568",
                "CVE-2014-0131", "CVE-2014-2523", "CVE-2014-2309", "CVE-2014-0100",
                "CVE-2014-0101", "CVE-2014-0049", "CVE-2014-0102", "CVE-2014-2039",
                "CVE-2014-0069", "CVE-2014-1874", "CVE-2014-1446", "CVE-2014-1438",
                "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-6376", "CVE-2013-6368",
                "CVE-2013-6367");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-13 19:37:00 +0000 (Thu, 13 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for kernel FEDORA-2015-3594");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"kernel on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-3594");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-March/151850.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC20");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC20")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.18.9~100.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
