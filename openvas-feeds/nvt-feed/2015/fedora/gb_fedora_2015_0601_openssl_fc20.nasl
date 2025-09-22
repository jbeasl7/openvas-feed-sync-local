# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.868936");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2015-01-21 05:44:43 +0100 (Wed, 21 Jan 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275",
                "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2014-3567",
                "CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3505", "CVE-2014-3506",
                "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510",
                "CVE-2014-3511", "CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198",
                "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-0160",
                "CVE-2013-4353", "CVE-2013-6450", "CVE-2013-6449");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");
  script_name("Fedora Update for openssl FEDORA-2015-0601");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"openssl on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-0601");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/148363.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
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

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~41.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
