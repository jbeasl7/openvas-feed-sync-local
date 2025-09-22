# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gnome:evolution";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900709");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1631");
  script_name("Evolution Mail Client Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_evolution_data_server_detect.nasl");
  script_mandatory_keys("Evolution/Ver");

  script_xref(name:"URL", value:"http://bugzilla.gnome.org/show_bug.cgi?id=581604");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34921");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=498648");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526409");

  script_tag(name:"impact", value:"Successful exploitation will let the local attacker gain sensitive information
  about the victim's mail folders and can view their contents.");

  script_tag(name:"affected", value:"Evolution Mail Client version 2.26.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to Mailer component in Evolution, uses world readable
  permissions for the .evolution directory and some other certain directories under .evolution which causes
  disclosure of sensitive information of the user's mail directories and their contents.");

  script_tag(name:"solution", value:"Upgrade to Evolution Mail Client version 2.30.1 or later.");

  script_tag(name:"summary", value:"Evolution for Linux is prone to an information disclosure vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less_equal(version:ver, test_version:"2.26.1")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"2.30.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
