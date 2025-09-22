# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871624");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:17 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054",
                "CVE-2016-4554", "CVE-2016-4556");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for squid RHSA-2016:1138-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Squid is a high-performance proxy caching
server for web clients, supporting FTP, Gopher, and HTTP data objects.

Security Fix(es):

  * A buffer overflow flaw was found in the way the Squid cachemgr.cgi
utility processed remotely relayed Squid input. When the CGI interface
utility is used, a remote attacker could possibly use this flaw to execute
arbitrary code. (CVE-2016-4051)

  * Buffer overflow and input validation flaws were found in the way Squid
processed ESI responses. If Squid was used as a reverse proxy, or for
TLS/HTTPS interception, a remote attacker able to control ESI components on
an HTTP server could use these flaws to crash Squid, disclose parts of the
stack memory, or possibly execute arbitrary code as the user running Squid.
(CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

  * An input validation flaw was found in Squid's mime_get_header_field()
function, which is used to search for headers within HTTP requests. An
attacker could send an HTTP request from the client side with specially
crafted header Host header that bypasses same-origin security protections,
causing Squid operating as interception or reverse-proxy to contact the
wrong origin server. It could also be used for cache poisoning for client
not following RFC 7230. (CVE-2016-4554)

  * An incorrect reference counting flaw was found in the way Squid processes
ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS
interception, an attacker controlling a server accessed by Squid, could
crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)");
  script_tag(name:"affected", value:"squid on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1138-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00052.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"squid", rpm:"squid~3.1.23~16.el6_8.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.1.23~16.el6_8.4", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
