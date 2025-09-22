# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.875411");
  script_version("2023-06-20T05:05:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-17480", "CVE-2018-17481", "CVE-2018-18335", "CVE-2018-18336",
                "CVE-2018-18337", "CVE-2018-18338", "CVE-2018-18339", "CVE-2018-18340",
                "CVE-2018-18341", "CVE-2018-18342", "CVE-2018-18343", "CVE-2018-18344",
                "CVE-2018-18345", "CVE-2018-18346", "CVE-2018-18347", "CVE-2018-18348",
                "CVE-2018-18349", "CVE-2018-18350", "CVE-2018-18351", "CVE-2018-18352",
                "CVE-2018-18353", "CVE-2018-18354", "CVE-2018-18355", "CVE-2018-18356",
                "CVE-2018-18357", "CVE-2018-18358", "CVE-2018-18359");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:27 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-17 21:15:00 +0000 (Sat, 17 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-01-16 04:03:50 +0100 (Wed, 16 Jan 2019)");
  script_name("Fedora Update for chromium FEDORA-2019-348547a32d");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC28");

  script_xref(name:"FEDORA", value:"2019-348547a32d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GPF6NWCKSBWW66XSYJGJYFDN4NBYOZ2U");

  script_tag(name:"summary", value:"The remote host is missing an update for the
  'chromium' package(s) announced via the FEDORA-2019-348547a32d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"affected", value:"chromium on Fedora 28.");

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

if(release == "FC28")
{

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~71.0.3578.98~1.fc28", rls:"FC28")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
