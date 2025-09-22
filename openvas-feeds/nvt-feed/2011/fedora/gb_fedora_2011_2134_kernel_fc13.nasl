# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-March/055238.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862910");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-11 14:43:00 +0000 (Tue, 11 Aug 2020)");
  script_xref(name:"FEDORA", value:"2011-2134");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2010-4165", "CVE-2011-0521", "CVE-2010-4346", "CVE-2010-4649", "CVE-2011-0006", "CVE-2010-4648", "CVE-2010-4650", "CVE-2010-4163", "CVE-2010-4668", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-3874", "CVE-2010-4162", "CVE-2010-4249", "CVE-2010-2962", "CVE-2010-2963", "CVE-2010-3698", "CVE-2010-3705", "CVE-2010-3442", "CVE-2010-4258", "CVE-2010-4169", "CVE-2010-4073", "CVE-2010-4072", "CVE-2010-3880", "CVE-2010-4082", "CVE-2010-3904", "CVE-2010-3432", "CVE-2010-3079", "CVE-2010-3080", "CVE-2010-3081", "CVE-2010-3301", "CVE-2010-3067", "CVE-2010-2960", "CVE-2010-2954", "CVE-2010-2955", "CVE-2010-2524", "CVE-2010-2478", "CVE-2010-2071", "CVE-2011-1044");
  script_name("Fedora Update for kernel FEDORA-2011-2134");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC13");
  script_tag(name:"affected", value:"kernel on Fedora 13");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.34.8~68.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
