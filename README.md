# DarkFalcon
Splunk-based dashboards and visuals for working with the MITRE ATT&amp;CK Framework

This is a lookup file driven system of dashboards helping work with the ATT&CK framework within a company and leveraging it for making business decisions. There is also an xml for adding the custome navigation to your Splunk nav.

<h1>Setup</h1>
Below are the steps you can follow to get DarkFalcon up and running in your Splunk instance.

<h2>1. Add Lookup Files</h2>
In Splunk, Click Settings then Lookups.
Click Lookup Table Files then New in the upper-left.
For each file in the Lookups Folder in the repo, add with the same name as the file.

Ensure permissions on the files are set to app, instead of owner or private, so others on your team can see them.


<h2>2. Create Dashboards</h2>
In Splunk, Click Dashboards then click Create new Dashboard button in the upper-right.
Set the following in the pop-up:
  Title: <name of the file in the Dashboard folder repo without the .xml extension>
  ID: <let it auto-populate>
  Permissions: Shared in App

When the new dashboard comes up, click edit source in the upper-right. Copy the XML from the file in the repo and paste it replacing the xml in the dashboard and click save.

Do this for each file in the Dashboard folder. These are already coded to use the lookup files that you added in the first section.


<h2>3. Update Navigation</h2>
This one is a little trickier and you have a couple of options for implementing it.

<h3>Option 1 - Update Nav XML from SSH</h3>
For this, SSH into you Splunk server and browse to the navigation folder of the app you added the dashboards to, usually search or SplunkEnterpriseSecuritySuite.

Copy the collection part of the nav xml from the Navigation folder of this repo and add it to the default.xml of the nav on your Splunk server. Save the file and refresh the site and you should see the links.

<h3>Option 2 - Create the Nav from the GUI</h3>
This is easiest through Enterprise Security Suite since they give you an easy to use page. In ESS, click Configue, then General then Navigation.

In the page, you will see the darkfalcon dashboards you created in step 2 and you can drag them to the right to stack them in the navigation bar. Use thhe xml from this repo under Navigation as an outline of how we we did our layout.



<h2>4. Setup Reports</h2>
Part of the reporting is a scheduled report that archives the scores so that they can be used for tracking over time. The other report is used for automated scoring and will be talked about in the blog.

In Splunk, click Settings thenSearches and Reports.
Click New and add the settings outlined in each report listed in the Reports folder of this repo.
