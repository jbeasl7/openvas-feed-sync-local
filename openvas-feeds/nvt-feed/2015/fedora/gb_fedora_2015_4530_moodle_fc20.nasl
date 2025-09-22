# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.869172");
  script_version("2023-06-20T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:27 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-04-06 07:13:30 +0200 (Mon, 06 Apr 2015)");
  script_cve_id("CVE-2014-3541", "CVE-2014-3542", "CVE-2014-3543", "CVE-2014-3544",
                "CVE-2014-3545", "CVE-2014-3546", "CVE-2014-3547", "CVE-2014-3548",
                "CVE-2014-3549", "CVE-2014-3550", "CVE-2014-3551", "CVE-2014-3552",
                "CVE-2014-3553", "CVE-2014-0213", "CVE-2014-0214", "CVE-2014-0215",
                "CVE-2014-0216", "CVE-2014-0217", "CVE-2014-0218", "CVE-2014-0122",
                "CVE-2014-0123", "CVE-2014-0124", "CVE-2014-0125", "CVE-2014-0126",
                "CVE-2014-0127", "CVE-2014-0129", "CVE-2014-0008", "CVE-2015-2269",
                "CVE-2015-2268", "CVE-2015-2267", "CVE-2015-2266", "CVE-2015-2272",
                "CVE-2015-2273", "CVE-2015-2270", "CVE-2015-2271", "CVE-2015-1493");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for moodle FEDORA-2015-4530");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"moodle on Fedora 20");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-4530");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154251.html");
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

  if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.6.10~1.fc20", rls:"FC20")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
